---
description: These artifacts collect information related to the windows network.
linktitle: Network
title: Network
weight: 40

---
## Windows.Network.ArpCache

Address resolution cache, both static and dynamic (from ARP, NDP).

Arg|Default|Description
---|------|-----------
wmiQuery|SELECT AddressFamily, Store, State, InterfaceIndex ...|
wmiNamespace|ROOT\\StandardCimv2|
kMapOfState|{\n "0": "Unreachable",\n "1": "Incomplete",\n "2" ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Network.ArpCache
description: Address resolution cache, both static and dynamic (from ARP, NDP).
parameters:
  - name: wmiQuery
    default: |
      SELECT AddressFamily, Store, State, InterfaceIndex, IPAddress,
             InterfaceAlias, LinkLayerAddress
      from MSFT_NetNeighbor
  - name: wmiNamespace
    default: ROOT\StandardCimv2

  - name: kMapOfState
    default: |
     {
      "0": "Unreachable",
      "1": "Incomplete",
      "2": "Probe",
      "3": "Delay",
      "4": "Stale",
      "5": "Reachable",
      "6": "Permanent",
      "7": "TBD"
     }

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET interfaces <=
          SELECT Index, HardwareAddr, IP
          FROM Artifact.Windows.Network.InterfaceAddresses()

      - |
        LET arp_cache = SELECT if(condition=AddressFamily=23,
                    then="IPv6",
                  else=if(condition=AddressFamily=2,
                    then="IPv4",
                  else=AddressFamily)) as AddressFamily,

               if(condition=Store=0,
                    then="Persistent",
                  else=if(condition=(Store=1),
                    then="Active",
                  else="?")) as Store,

               get(item=parse_json(data=kMapOfState),
                   member=encode(string=State, type='string')) AS State,
               InterfaceIndex, IPAddress,
               InterfaceAlias, LinkLayerAddress
            FROM wmi(query=wmiQuery, namespace=wmiNamespace)
      - |
        SELECT * FROM foreach(
          row=arp_cache,
          query={
             SELECT AddressFamily, Store, State, InterfaceIndex,
                    IP AS LocalAddress, HardwareAddr, IPAddress as RemoteAddress,
                    InterfaceAlias, LinkLayerAddress AS RemoteMACAddress
             FROM interfaces
             WHERE InterfaceIndex = Index
          })
```
   {{% /expand %}}

## Windows.Network.InterfaceAddresses

Network interfaces and relevant metadata.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Network.InterfaceAddresses
description: Network interfaces and relevant metadata.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET interface_address =
           SELECT Index, MTU, Name, HardwareAddr, Flags, Addrs
           from interfaces()

      - |
        SELECT Index, MTU, Name, HardwareAddr.String As HardwareAddr,
           Flags, Addrs.IP as IP, Addrs.Mask.String as Mask
        FROM flatten(query=interface_address)
```
   {{% /expand %}}

## Windows.Network.ListeningPorts

Processes with listening (bound) network sockets/ports.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Network.ListeningPorts
description: Processes with listening (bound) network sockets/ports.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET process <= SELECT Name, Pid from pslist()

      - |
        SELECT * from foreach(
          row={
            SELECT Pid AS PortPid, Laddr.Port AS Port,
                   TypeString as Protocol, FamilyString as Family,
                   Laddr.IP as Address
            FROM netstat() where Status = 'LISTEN'
          },
          query={
            SELECT Pid, Name, Port, Protocol, Family, Address
            FROM process where Pid = PortPid
          })
```
   {{% /expand %}}

## Windows.Network.Netstat

Show information about open sockets. On windows the time when the
socket was first bound is also shown.


{{% expand  "View Artifact Source" %}}


```text
name: Windows.Network.Netstat
description: |
  Show information about open sockets. On windows the time when the
  socket was first bound is also shown.

sources:
- precondition: SELECT OS From info() where OS = 'windows'
  queries:
  - LET processes <= SELECT Name, Pid AS ProcPid FROM pslist()
  - SELECT Pid, {
        SELECT Name from processes
        WHERE Pid = ProcPid
      } AS Name, FamilyString as Family,
      TypeString as Type,
      Status,
      Laddr.IP, Laddr.Port,
      Raddr.IP, Raddr.Port,
      Timestamp
    FROM netstat()
```
   {{% /expand %}}

## Windows.Network.NetstatEnriched

NetstatEnhanced adds addtional data points to the Netstat artifact and
enables verbose search options.

Examples include: Process name and path, authenticode information or
network connection details.


Arg|Default|Description
---|------|-----------
IPRegex|.*|regex search over IP address fields.
PortRegex|.*|regex search over port fields.
Family|ALL|IP version family selection
Type|ALL|Transport protocol type selection
Status|ALL|TCP status selection
ProcessNameRegex|.*|regex search over source process name
ProcessPathRegex|.*|regex search over source process path
CommandLineRegex|.*|regex search over source process commandline
HashRegex|.*|regex search over source process hash
UsernameRegex|.*|regex search over source process user context
AuthenticodeSubjectRegex|.*|regex search over source Authenticode Subject
AuthenticodeIssuerRegex|.*|regex search over source Authenticode Issuer
AuthenticodeVerified|ALL|Authenticode signiture selection

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Network.NetstatEnriched
description: |
  NetstatEnhanced adds addtional data points to the Netstat artifact and
  enables verbose search options.

  Examples include: Process name and path, authenticode information or
  network connection details.

author: "Matthew Green - @mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: IPRegex
    description: "regex search over IP address fields."
    default:  ".*"
  - name: PortRegex
    description: "regex search over port fields."
    default: ".*"

  - name: Family
    description: "IP version family selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - IPv4
       - IPv6
  - name: FamilyMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      IPv4,"^IPv4$"
      IPv6,"^IPv6$"

  - name: Type
    description: "Transport protocol type selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - TCP
       - UDP
  - name: TypeMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      TCP,"^TCP$"
      UDP,"^UDP$"

  - name: Status
    description: "TCP status selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - ESTABLISHED
       - LISTENING
       - OTHER
  - name: StatusMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      ESTABLISHED,"^ESTAB$"
      LISTENING,"^LISTEN$"
      OTHER,"CLOS|SENT|RCVD|LAST|WAIT|DELETE"

  - name: ProcessNameRegex
    description: "regex search over source process name"
    default: ".*"
  - name: ProcessPathRegex
    description: "regex search over source process path"
    default: ".*"
  - name: CommandLineRegex
    description: "regex search over source process commandline"
    default: ".*"
  - name: HashRegex
    description: "regex search over source process hash"
    default: ".*"
  - name: UsernameRegex
    description: "regex search over source process user context"
    default: ".*"
  - name: AuthenticodeSubjectRegex
    description: "regex search over source Authenticode Subject"
    default: ".*"
  - name: AuthenticodeIssuerRegex
    description: "regex search over source Authenticode Issuer"
    default: ".*"
  - name: AuthenticodeVerified
    description: "Authenticode signiture selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - TRUSTED
       - UNSIGNED
       - NOT TRUSTED
  - name: AuthenticodeVerifiedMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      TRUSTED,"^trusted$"
      UNSIGNED,"^unsigned$"
      NOT TRUSTED,"unsigned|disallowed|untrusted|error"

sources:
  - name: Netstat
    queries:
      - LET VerifiedRegex <= SELECT Regex
            FROM parse_csv(filename=AuthenticodeVerifiedMap, accessor="data")
            WHERE Choice=AuthenticodeVerified LIMIT 1
      - LET StatusRegex <= SELECT Regex
            FROM parse_csv(filename=StatusMap, accessor="data")
            WHERE Choice=Status LIMIT 1
      - LET FamilyRegex <= SELECT Regex
            FROM parse_csv(filename=FamilyMap, accessor="data")
            WHERE Choice=Family LIMIT 1
      - LET TypeRegex <= SELECT Regex
            FROM parse_csv(filename=TypeMap, accessor="data")
            WHERE Choice=Type LIMIT 1

      - LET process <= SELECT Pid as PsId,
            Ppid,
            Name,
            CommandLine,
            Exe,
            Hash,
            Authenticode,
            Username
        FROM Artifact.Windows.System.Pslist()
        WHERE Name =~ ProcessNameRegex

      - SELECT Pid,
            { SELECT Ppid FROM process WHERE PsId = Pid } as Ppid,
            { SELECT Name FROM process WHERE PsId = Pid } as Name,
            { SELECT Exe FROM process WHERE PsId = Pid } as Path,
            { SELECT CommandLine FROM process WHERE PsId = Pid } as CommandLine,
            { SELECT Hash FROM process WHERE PsId = Pid } as Hash,
            { SELECT Username FROM process WHERE PsId = Pid } as Username,
            { SELECT Authenticode FROM process WHERE PsId = Pid } as Authenticode,
            FamilyString as Family,
            TypeString as Type,
            Status,
            Laddr.IP, Laddr.Port,
            Raddr.IP, Raddr.Port,
            Timestamp
        FROM netstat()
        WHERE Path =~ ProcessPathRegex
            and CommandLine =~ CommandLineRegex
            and Username =~ UsernameRegex
            and ( Hash.MD5 =~ HashRegex
              or Hash.SHA1 =~ HashRegex
              or Hash.SHA256 =~ HashRegex
              or not Hash )
            and ( Authenticode.IssuerName =~ AuthenticodeIssuerRegex or not Authenticode )
            and ( Authenticode.SubjectName =~ AuthenticodeSubjectRegex or not Authenticode )
            and ( Authenticode.Trusted =~ VerifiedRegex.Regex[0] or not Authenticode )
            and Status =~ StatusRegex.Regex[0]
            and Family =~ FamilyRegex.Regex[0]
            and Type =~ TypeRegex.Regex[0]
            and ( format(format="%v", args=Laddr.IP) =~ IPRegex
                or format(format="%v", args=Raddr.IP) =~ IPRegex )
            and ( format(format="%v", args=Laddr.Port) =~ PortRegex
                or format(format="%v", args=Raddr.Port) =~ PortRegex )
```
   {{% /expand %}}

