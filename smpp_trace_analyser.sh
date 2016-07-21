#!/bin/bash
 
# "latency" data file.
latency_data="latency.dat"
# "gnuplot" script.
gnuplot_script="gnuplot.sh"
# "tshark" executable.
tshark_executable="tshark.exe"
# "gnuplot" executable.
gnuplot_executable="wgnuplot.exe"
# "smpp" script in "lua" programming language.
lua_smpp_script=''
# "tcp trace" file (pcap).
tcp_trace_file=''
# specify (optionally) the "tcp port" being used by the "smpp" traffic.
smpp_port=''

# create an associative array.
declare -A skip_error
# put a value into an associative array.
skip_error[$"The NPF driver isn't running.  You may have trouble capturing or listing interfaces."]=true

# set script name variable.
script=`basename ${BASH_SOURCE[0]}`

# set fonts for help.
NORM=`tput sgr0`
BOLD=`tput bold`

function executable_in_path() 
{
    if type $1 >/dev/null 2>&1 ; then
		echo "-n"
	else
		echo -e "\\n${BOLD}error${NORM} : '$1' not found; add the '$1' executable to your 'PATH' (on Windows) so you can open a command prompt and use it from any directory.\\n"
		exit 1
    fi
}

# help function.
function help()
{
	echo -e "\\nusage: ${BOLD}$script [ -p smpp_port ] -l lua_smpp_script -f tcp_trace_file${NORM}\\n"
	exit 1
}

executable_in_path $tshark_executable 
executable_in_path $gnuplot_executable 

# check the number of arguments. If none are passed, print help and exit.
if [ $# -eq 0 ]; then
  help
fi

# start "getopts" code; parse command line flags.
while getopts hl:f:p: flag; do
	case $flag in
		h)  # show help (optional option).
			help
			;;
		l)  # set option "l" for "lua" script (mandatory option).
			lua_smpp_script=$OPTARG
			;;		
		f)  # set option "f" for "tcp trace" file ("pcap"; mandatory option).
			tcp_trace_file=$OPTARG
			;;	
		p)  # set option "p" for "smpp" port (optional option).
			# Like Wireshark's "Decode As..." feature : "-d <layer type>==<selector>,<decode-as protocol>", this lets us 
			# specify how a layer type should be dissected. If the layer type in question - for example, "tcp.port" for a 
			# "tcp" port number - has the specified "selector" value, packets should be dissected as the specified
			# "protocol" ("decode-as protocol = smpp" in our case by default).
			# So finally, we define the following command line "tshark" input argument : "-d tcp.port==smpp_port,smpp",
			# decoding any traffic running over the specified "tcp port" as "smpp".
			smpp_port=$OPTARG
			;;						
		?) # unrecognised option.
			echo -e "\\nuse ${BOLD}$script -h${NORM} to see the help documentation.\\n"
			exit 2
			;;
	esac
done

# tell "getopts" to move on to the next argument.
shift $((OPTIND-1))  

if [ -z "$lua_smpp_script" ]; then
	echo -e "\\n${BOLD}error${NORM} : missing -l option for 'smpp' parsing script in 'lua'."
	echo -e "\\nuse ${BOLD}$script -h${NORM} to see the help documentation.\\n"
	exit 1
elif [ ! -f "$lua_smpp_script" ]; then	
	echo -e "\\n${BOLD}error${NORM} : '$lua_smpp_script' smpp parsing script in 'lua' not found.\\n"
	exit 1
fi

if [ -z "$tcp_trace_file" ]; then
	echo -e "\\n${BOLD}error${NORM} : missing -f option for 'tcp trace' file."
	echo -e "\\nuse ${BOLD}$script -h${NORM} to see the help documentation.\\n"
	exit 1
elif [ ! -f "$tcp_trace_file" ]; then	
	echo -e "\\n${BOLD}error${NORM} : '$tcp_trace_file' tcp-trace file not found.\\n"
	exit 1
fi

if [ ! -z "$smpp_port" ]; then
	smpp_port="-d tcp.port==$smpp_port,smpp"
fi

echo ""
# sudo tcpdump -v -nn -s 0 -w tcp_trace_file.pcap -i ethernet_interface host xxx.xxx.xxx.xxx and port xxxx
stderr=$( $tshark_executable $smpp_port -q -nr $tcp_trace_file -2 -z smpp_commands,tree -z expert -Xlua_script:$lua_smpp_script -Xlua_script1:$latency_data -Xlua_script1:$gnuplot_script -Xlua_script1:$gnuplot_executable 2>&1 >/dev/tty )
# remove all "\r\n" from "error" (if any) and replace them with a "white space" character.
stderr=${stderr//$'\r\n'/ }
stderr=${stderr//$'\r'/}
# if "error" is not null and it is missing from the associative array,
if [[ ! -z "$stderr" && ! ${skip_error[$stderr]+_} ]]; then
	echo -e "\\n${BOLD}error${NORM} : $stderr\\n"
	echo -e "${BOLD}warn : script will exit now ...${NORM}\\n"
	# then exit; else skip error and resume operation.
	exit 1
fi

if [ $? -ne 0 ]; then
	echo ""
	exit 1
fi

if [ -f $latency_data ]; then	
	if [ -f $gnuplot_script ]; then
		echo -e "\\n${BOLD}warn${NORM} : '$gnuplot_executable' should now be running as a background process; you should also close (any) graphs to exit completely normally.\\n"
		. ./gnuplot.sh & #>/dev/null 2>/dev/null		
	else
		echo -e "\\n${BOLD}error${NORM} : cannot plot 'latency' graphs ; '$gnuplot_script' temp script file not found.\\n"
		echo -e "${BOLD}warn : script will exit now ...${NORM}\\n"
		rm -f $latency_data 
	fi	
else
	echo -e "\\n${BOLD}error${NORM} : cannot plot 'latency' graphs ; '$latency_data' temp data file not found.\\n"
	echo -e "${BOLD}warn : script will exit now ...${NORM}\\n"
	rm -f $gnuplot_script
fi

exit 0
