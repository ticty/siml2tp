#!/bin/sh


DIALOG=zenity
config_dir=@CONFIG_DIR@

siml2tp_config=$HOME/$config_dir/siml2tp.conf
siml2tp_config_tpl=$HOME/$config_dir/siml2tp.conf.tpl
ppp_config=$HOME/$config_dir/ppp.conf


title="模式选择"
text="从下面选择一项以继续"
result=""

result=`$DIALOG --list --title="$title" --text="$text" --column="设置模式" "向导设置" "手动编辑"`

case "$result" in
	"手动编辑")
		while true
		do
			title="选择配置文件"
			text="请从下面选择配置文件"
			result=`$DIALOG --list  --title="$title" --text="$text" --column="配置类型" "siml2tp配置" "ppp配置"`
			
			case "$result" in
				"siml2tp配置")
					if [ ! -e $siml2tp_config ]
					then
						echo "cannot found file $siml2tp_config"
						exit 1
					fi
					
					$DIALOG --text-info --width=800 --height=600 --title="$siml2tp_config" --filename="$siml2tp_config" --editable 1>/tmp/tmp_$$.txt
					
					if [ $? -eq 0 ]
					then
						mv /tmp/tmp_$$.txt $siml2tp_config
						chmod 600 $siml2tp_config
					fi
					
					rm -f /tmp/tmp_$$.txt
				;;
				
				"ppp配置")
					if [ ! -e $ppp_config ]
					then
						echo "cannot found file $ppp_config"
						exit 1
					fi
					
					$DIALOG --text-info --width=800 --height=600 --title="$ppp_config" --filename="$ppp_config" --editable 1>/tmp/tmp_$$.txt
					
					if [ $? -eq 0 ]
					then
						mv /tmp/tmp_$$.txt $ppp_config
						chmod 640 $ppp_config
					fi
					
					rm -f /tmp/tmp_$$.txt
				;;
				
				*)
					exit 0
				;;
			esac
		done
		
		exit 0
	;;

	"向导设置")
		if [ ! -e $siml2tp_config_tpl ]
		then
			echo "cannot found file $siml2tp_config_tpl"
			exit 1
		fi

		title="用户名"
		text="请填写上网帐号，留空则登录时终端输入"
		username=`$DIALOG --entry --title="$title" --text="$text"`
		
		title="密码"
		text="请填写上网密码，留空则登录时终端输入"
		passwd=`$DIALOG --entry --title="$title" --text="$text" --hide-text`
		
		title="认证服务器"
		text="请填写认证服务器IP地址"
		addr=`$DIALOG --entry --title="$title" --text="$text" --entry-text="10.255.201.5"`
		
		title="认证服务器端口"
		text="请填写认证服务器端口，默认1701"
		port=`$DIALOG --entry --title="$title" --text="$text" --entry-text="1701"`
		
		title="路由"
		text="请填写拨号认证时的本地静态路由表项(网段 + 子网掩码)"
		route=`$DIALOG --entry --title="$title" --text="$text" --entry-text="10.0.0.0 255.0.0.0"`
		
		
		title="ppp"
		text="请填写ppp可执行路径"
		
		ppp_guest=`which pppd`
		if [ $? -ne 0 ]
		then
			if [ -e "/usr/sbin/pppd" ]	# default /usr/sbin/pppd
			then
				ppp_guest="/usr/sbin/pppd"
			fi
		fi
		
		ppp_path=`$DIALOG --entry --title="$title" --text="$text" --entry-text="$ppp_guest"`
		
		sed -e "s#@USERNAME@#${username}#g" \
			-e "s#@PASSWORD@#${passwd}#g" \
			-e "s#@HOST@#${addr}:${port}#g" \
			-e "s#@ROUTE@#${route}#g" \
			-e "s#@PPPD@#${ppp_path}#g" $siml2tp_config_tpl > $siml2tp_config
		
		chmod 600 $siml2tp_config
		
		echo ""
		echo "配置完成！"
		echo ""
		
		exit 0
	;;

	*)
		exit 0
esac

exit 0

