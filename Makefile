#################################################
# Makefile for SimL2tp
# bugs report to <dev.guofeng@gmail.com>
#################################################


INSTALL =   install


# target name
SIML2TP     = siml2tp
PPP_PLUGIN  = passwordfd.so

Target  = $(SIML2TP) $(PPP_PLUGIN) siml2tp-conf


# install info
config      = conf/ppp.conf \
              conf/siml2tp.conf \
              conf/siml2tp.conf.tpl

bin_prefix  = /usr/local/bin
config_dir  = .siml2tp


# compile & link config
CC  = gcc

DEFINES = 

CFLAGS  = -mtune=native -march=native -pipe \
		  -O3 -Wall -W -Werror \
          -MMD -MP -MF "$(@:%.o=%.d)" -MT "$@" -MT "$(@:%.o=%.d)"

LDFLAGS = 

OBJ_DIR = .obj


# source & object
SIML2TP_SRCS    = main.c \
                  siml2tp.c \
                  avp.c \
                  schedule.c \
                  misc.c \
                  timer.c \
                  network.c

SIML2TP_OBJS    = ${SIML2TP_SRCS:%.c=$(OBJ_DIR)/%.o}

SIML2TP_DEPS    = ${SIML2TP_OBJS:.o=.d}


# make rule
all: $(Target)


-include $(SIML2TP_DEPS)


$(SIML2TP): $(SIML2TP_OBJS)
	@$(CC) $(LDFLAGS) -o "$@" $(SIML2TP_OBJS)
	@chmod 755 "$@"
	@echo ""
	@echo "### Bulid $@ success ###"
	@echo ""


%.so: plugin/%.c
	$(CC) -o "$@" -O3 -Wall -W -shared -fPIC "$<"
	@chmod 664 "$@"
	@echo ""
	@echo "### Bulid $@ success ###"
	@echo ""


siml2tp-conf: siml2tp-conf.tpl Makefile
	@sed 's/@CONFIG_DIR@/$(config_dir)/g' siml2tp-conf.tpl > "$@"
	@chmod 755 "$@"


$(OBJ_DIR)/%.o: %.c
	@test -d $(OBJ_DIR) || mkdir -p -m 777 $(OBJ_DIR)
	$(CC) $(DEFINES) $(CFLAGS) -c "$<" -o "$@"
	@chmod 666 "$@"
	@chmod 666 "$(@:%.o=%.d)"
	@echo ""


strip:
	strip $(SIML2TP)
	strip $(PPP_PLUGIN)

permission:
	@if [ `id -u` -eq 0 ]; \
	then \
		exit 0; \
	else \
		echo "*** please run with root permission ***"; \
		exit 1; \
	fi


install: permission $(config) $(Target)
	@mkdir -p $(bin_prefix)
	@$(INSTALL) -o 0 -g 0 -m 4555 -s $(SIML2TP) $(bin_prefix)/$(SIML2TP)
	@$(INSTALL) -o 0 -g 0 -m 755 siml2tp-conf $(bin_prefix)/siml2tp-conf
	@for user_path in `awk -F: \
	'$$3 > 500 || $$3 == 0 { printf "%s:%s:%s\n", $$3,$$4,$$6 }' /etc/passwd`; \
	do \
		uid=`echo $$user_path | awk -F : '{print $$1}'`; \
		gid=`echo $$user_path | awk -F : '{print $$2}'`; \
		home=`echo $$user_path | awk -F : '{print $$3}'`; \
		if [ -d $$home ]; \
		then \
			$(INSTALL) -o $$uid -g $$gid -m 744 -d $$home/$(config_dir); \
			$(INSTALL) -o $$uid -g $$gid -m 600 -s $(PPP_PLUGIN) $$home/$(config_dir)/$(PPP_PLUGIN); \
			$(INSTALL) -o $$uid -g $$gid -m 754 after-connect $$home/$(config_dir)/after-connect; \
			$(INSTALL) -o $$uid -g $$gid -m 754 before-exit $$home/$(config_dir)/before-exit; \
			$(INSTALL) -o $$uid -g $$gid -m 640 conf/ppp.conf $$home/$(config_dir)/ppp.conf; \
			$(INSTALL) -o $$uid -g $$gid -m 600 conf/siml2tp.conf $$home/$(config_dir)/siml2tp.conf; \
			$(INSTALL) -o $$uid -g $$gid -m 444 conf/siml2tp.conf.tpl $$home/$(config_dir)/siml2tp.conf.tpl; \
		fi \
	done
	@echo ""
	@echo "Install finish"
	@echo ""


uninstall: permission
	@rm -f $(bin_prefix)/$(SIML2TP)
	@rm -f $(bin_prefix)/siml2tp-conf
	@for path in `awk -F: \
	'$$3 > 500 || $$3 == 0 { print $$6 }' /etc/passwd`; \
	do \
		if [ -d $$path ]; \
		then \
			rm -rf $$path/$(config_dir); \
		fi \
	done
	@echo ""
	@echo "Uninstall finish"
	@echo ""


clean:
	@rm -f $(SIML2TP_OBJS) $(Target) $(SIML2TP_DEPS)
	@rm -rf $(OBJ_DIR)
	@echo ""
	@echo "Clean finish"
	@echo ""


.PHONY: all strip permission clean install uninstall

#end of makefile
