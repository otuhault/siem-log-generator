```
#!/bin/sh
RETVAL=0
USER=splunk

. /etc/init.d/functions

# disable hugepages
disable_huge() {
echo "disabling huge page support"
THP=`find /sys/kernel/mm/ -name transparent_hugepage -type d | tail -n 1`
for SETTING in "enabled" "defrag";do
	if test -f ${THP}/${SETTING}; then
		echo never > ${THP}/${SETTING}
	fi
done
}

# change ulimits
change_ulimit() {
	ulimit -Hn 65535
	ulimit -Sn 65535
	ulimit -Hu 20480
	ulimit -Su 20480
	ulimit -Hf unlimited
	ulimit -Sf unlimited
}

splunk_start() {
	echo Starting Splunk...
	/bin/su - ${USER} -c '"/opt/splunk/bin/splunk" start --no-prompt --answer-yes'
	RETVAL=$?
	[ $RETVAL -eq 0 ] && touch /var/lock/subsys/splunk
}

splunk_stop() {
	echo Stopping Splunk...
	/bin/su - ${USER} -c '"/opt/splunk/bin/splunk" stop'
	RETVAL=$?
	[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/splunk
}

splunk_restart() {
	echo Restarting Splunk...
	/bin/su - ${USER} -c '"/opt/splunk/bin/splunk" restart'
	RETVAL=$?
	[ $RETVAL -eq 0 ] && touch /var/lock/subsys/splunk
}

splunk_status() {
	echo Splunk status:
	/bin/su - ${USER} -c '"/opt/splunk/bin/splunk" status'
	RETVAL=$?
}

case "$1" in
start)
	disable_huge
	change_ulimit
	splunk_start
	;;
stop)
	splunk_stop
	;;
restart)
	disable_huge
	change_ulimit
	splunk_restart
	;;
status)
	splunk_status
	;;
*)
echo "Usage: $0 {start|stop|restart|status}"
exit 1
;;
esac
exit $RETVAL
```
