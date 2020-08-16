all:
	rm -rf docs/
	hugo

watch:
	hugo serve
