-- TODO : tcp latency stats

-- Implements a "tap" in "lua". "Taps" are a mechanism to fetch data from every frame. They can be defined to use a "display filter".
-- This "tap" is meant to be used as a script run by "tshark". 
-- To run this "tap" generally on a "tcp_trace.pcap" file and assuming that "tshark" is in the path, one would issue the command : 
-- "tshark -X lua_script:script.lua -r tcp_trace.pcap".

local debug = false

local submit_sm_cmd_id      = '0x00000004'
local submit_sm_resp_cmd_id = '0x80000004'

-- use "display filter" syntax here :
local filter = 'smpp.command_id==' .. submit_sm_cmd_id .. ' || smpp.command_id==' .. submit_sm_resp_cmd_id 
-- first, we declare the "tap" with the "filter" it is going to use.
local smpp_tap 	 = Listener.new( "smpp", filter )
local tcp_tap 	 = Listener.new( "tcp" )

-- declare field extractors for your named fields.
-- frame :
local frame_relativetime = Field.new( "frame.time_relative" )
local frame_number 		 = Field.new( "frame.number" )
-- tcp :
local tcp_stream 		 = Field.new( "tcp.stream" )
-- smpp :
local smpp_cmd 			 = Field.new( "smpp.command_id" )
local smpp_seq 			 = Field.new( "smpp.sequence_number" )

local frame_id = 0
local pdu_in_frame_ctr = 1

-----------------------------------------------------------------------------------------------------------------------------

local streams = {}
local transactions = {}

local number_of_trace_frames = 0
local trace_duration = 0

local time_relative_of_first_completed_transaction = 0
local time_relative_of_last_completed_transaction = 0

-- "window" title.
local window_title = "latency | statistics"
-- "latency" label.
local latency_label = "latency"
-- "frequency distribution" label.
local frequency_distribution_label = "frequency"
-- "cumulative distribution" label.
local cumulative_distribution_label = "cumulative"
-- "time" label.
local time_label = "time"
-- "histogram | latency" graph title.
local histogram_latency_title = "histogram | latency [sec]"
-- "latency" graph title.
local latency_title = "latency [sec] vs time [sec]"

-- put the passed-in "args" into a table. Access the passed-in arguments through the '...' "lua varargs" notation.
local args = {...}
-- "latency" data file.
local latency_data = args[ 1 ]
-- "gnuplot" script.
local gnuplot_script = args[ 2 ]
-- "gnuplot" executable.
gnuplot_executable = args[ 3 ]

-----------------------------------------------------------------------------------------------------------------------------

local function print_transactions()

	for i = 1, #transactions do
		print( string.format( "%5d %7.3f %2d %s %7.3f",
			transactions[ i ][ 1 ],
			transactions[ i ][ 2 ],
			transactions[ i ][ 3 ],
			transactions[ i ][ 4 ],
			transactions[ i ][ 5 ]
		) )
	end
	
end

-----------------------------------------------------------------------------------------------------------------------------

local function save_transactions_latency()

	-- open a file in "write" mode.
	file = io.open( latency_data , "w" )

	-- set the default "output" file.
	io.output( file )
	
	-- print data into the file.
	for i = 1, #transactions do			
		io.write( string.format( "%.3f %.3f\n", transactions[ i ][ 2 ], transactions[ i ][ 5 ] ) )
	end
	
	-- close the open file.
	io.close( file )
	
end

-----------------------------------------------------------------------------------------------------------------------------

local function save_gnuplot_script( script )

	-- open a file in "write" mode.
	file = io.open( gnuplot_script , "w" )

	-- set the default "output" file.
	io.output( file )
	
	-- print data into the file.
	io.write( script )
	
	-- close the open file.
	io.close( file )
	
end

-----------------------------------------------------------------------------------------------------------------------------

local function tcp_streams()

	local ctr = 0 
	
	for _ in pairs(streams) do
		ctr = ctr + 1
	end
	
	return( ctr )
	
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get the "mean" value of a table.

local function latency_mean( )

  local sum = 0
  local ctr = 0

  for i = 1, #transactions do
      sum = sum + transactions[ i ][ 5 ]
      ctr = ctr + 1    
  end

  return ( sum / ctr )
  
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get the "median" of a table.

local function latency_median()
  
  local temp = {}

  -- deep copy table so that when we sort it, the original is unchanged.
  for i = 1, #transactions do
      table.insert( temp, transactions[ i ][ 5 ] )
  end

  table.sort( temp )

  -- If we have an even number of table elements or odd.
  if math.fmod( #temp, 2 ) == 0 then
    -- return "mean" value of middle two elements.
    return ( temp[ #temp / 2 ] + temp[ ( #temp / 2 ) + 1 ] ) / 2
  else
    -- return middle element.
    return temp[ math.ceil( #temp / 2 ) ]
  end
  
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get the "standard deviation" of a table.

local function latency_standardDeviation()

  local vm
  local sum = 0
  local ctr = 0

  local mean = latency_mean()

  for i = 1, #transactions do
      vm = transactions[ i ][ 5 ] - mean
      sum = sum + ( vm * vm )
      ctr = ctr + 1
  end

  return( math.sqrt( sum / ( ctr - 1 ) ) )
  
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get the "max" for a table.

local function latency_max()

  local max = -math.huge

  for i =1, #transactions do
      max = math.max( max, transactions[ i ][ 5 ] )
  end

  return max
  
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get the "min" for a table.

local function latency_min()

  local min = math.huge

  for i=1, #transactions do
      min = math.min( min, transactions[ i ][ 5 ] )    
  end

  return min
  
end

-----------------------------------------------------------------------------------------------------------------------------
-- Get "properties" of the "transaction" that corresponds to the given "latency" in "capture".

local function transaction_of_latency( latency )

    for i=1, #transactions do
        if latency == transactions[ i ][ 5 ] then 
			return { transactions[ i ] }
		end
    end
	
end

-----------------------------------------------------------------------------------------------------------------------------
-- This function is going to be called once each time the filter of the "tap" matches.

function smpp_tap.packet(pinfo,tvb)

	local framenumber 		= tonumber( tostring( frame_number()) )
	local framerelativetime = tonumber( tostring( frame_relativetime() ) )
	local stream 			= tonumber( tostring( tcp_stream()) )
	-- a single "frame" (i.e. a single "ip" packet and "tcp" segment), may include multiple "smpp" packets; 
	-- so, we have to put the "smpp" field selector in "{}" brackets and it will return a table consisting of the corresponding 
	-- "smpp" pdu data. Have a look also below at a related comment.
	local smppcmd_of_pdu_in_frame = { smpp_cmd() }
	local smppseq_of_pdu_in_frame = { smpp_seq() }

	-- a single "frame" (i.e. a single "ip" packet and "tcp" segment), may include multiple "smpp" packets.
	-- so, we have to put the "smpp" field selector in "{}" brackets and it will return a table consisting of the corresponding 
	-- "smpp" pdu data. But also we need to keep "state" information about the current "frame" (using "frame" number as an 
	-- "index") as well as about what "smpp" pdu the "tap.packet()" has already retrieved for the current "frame".
	-- Briefly the above strategy is necessary because: by tapping the "smpp" layer, the "tap.packet()" function gets called for 
	-- each separate "smpp" message. For a given however "ip" packet (frame), the first time "tap.packet()" runs for "ip" packet #1, 
	-- we'll only get the various "fields" we're interested in for the first "smpp"; but unfortunately the second time the 
	-- "tap.packet()" is called, it will get the "fields" from both the first and second "smpp" message; and the third time 
	-- "tap.packet()" is invoked it will get the "fields" from all three messages and so on.
	if frame_id == framenumber then	
		-- retrieve information from the same "frame"; i.e. "smpp" pdu has been found - increment "pdu" counter by 1.
		pdu_in_frame_ctr = pdu_in_frame_ctr + 1
	else
		-- retrieve information from a new "frame"; initialize "pdu" counter and store the number of the current "frame" for 
		-- future reference.
		pdu_in_frame_ctr = 1
		frame_id = framenumber 		
	end
	-- use "pdu" counter and retrieve (field) data from the corresponding "smpp" pdu only in the current "frame", skipping 
	-- "smpp" pdu/fields already retrieved.
	smppcmd = tostring( smppcmd_of_pdu_in_frame[ pdu_in_frame_ctr ] )
	smppseq = tostring( smppseq_of_pdu_in_frame[ pdu_in_frame_ctr ] )
	
	if debug then	
		print( string.format( "%5d %7.3f %2d %s %s",
			framenumber,
			framerelativetime,
			stream,
			smppcmd,
			smppseq
		) )
	end
		
	if smppcmd == submit_sm_cmd_id or smppcmd == submit_sm_resp_cmd_id then
	
		if streams[ stream ] == nil then
			streams[ stream ] = {}
		end
	
		if smppcmd == submit_sm_cmd_id then					
			streams[ stream ][ smppseq ] = {}	
			table.insert( streams[ stream ][ smppseq ], { framenumber, framerelativetime, smppcmd } )				
		else
			if streams[ stream ][ smppseq ] ~= nil then	
				if time_relative_of_first_completed_transaction == 0 then
					time_relative_of_first_completed_transaction = framerelativetime
				end
			
				time_relative_of_last_completed_transaction = framerelativetime
			
				framerelativetime = framerelativetime - streams[ stream ][ smppseq ][ 1 ][ 2 ]
				
				table.insert( transactions, { framenumber, time_relative_of_last_completed_transaction, stream, smppseq, framerelativetime } )
			end				
		end	
	end	
	
end

-----------------------------------------------------------------------------------------------------------------------------
-- This function is going to be called once each time the filter of the "tap" matches.

function tcp_tap.packet(pinfo,tvb)

	local framenumber 		= tonumber( tostring( frame_number()) )
	local framerelativetime = tonumber( tostring( frame_relativetime() ) )

	trace_duration = framerelativetime
	number_of_trace_frames = framenumber

end

-----------------------------------------------------------------------------------------------------------------------------
-- This function will get called at the end of the "capture" to print the summary.

function smpp_tap.draw()

	if debug then
		print_transactions()
	end
	
	-- "latency" : max value.
	local latency_max = latency_max()
	-- "latency" : min value.
	local latency_min = latency_min()

	local transaction_with_max_latency = transaction_of_latency( latency_max )
	local transaction_with_min_latency = transaction_of_latency( latency_min )
	
	print( "" )
	print( "trace details" )
	print( "=============" )
	print( " frames                : " .. number_of_trace_frames )
	print( " duration              : " .. string.format( "%.3f", trace_duration ) )		
	print( " tcp streams           : " .. tcp_streams() )
	print( " transactions          : " .. #transactions )
	print( " relative time of first  " ) 
	print( " completed transaction : " .. string.format( "%.3f", time_relative_of_first_completed_transaction ) )	
	print( " relative time of last   " ) 
	print( " completed transaction : " .. string.format( "%.3f", time_relative_of_last_completed_transaction ) )
	print( "" )
	print( "statistics" )
	print( "=============" )
	print( " latency mean    : " .. string.format( "%.3f", latency_mean() ) )
	print( " latency median  : " .. string.format( "%.3f", latency_median() ) )
	print( " latency std dev : " .. string.format( "%.3f", latency_standardDeviation() ) )
	print( " latency max     : " .. string.format( "%.3f [ tcp_stream # %d seqnum # %d | submit_sm-resp : frame # %d rel_time = %.3f --> submit_sm : frame # %d rel_time = %.3f ]", latency_max, transaction_with_max_latency[ 1 ][ 3 ], transaction_with_max_latency[ 1 ][ 4 ], transaction_with_max_latency[ 1 ][ 1 ], transaction_with_max_latency[ 1 ][ 2 ], streams[ transaction_with_max_latency[ 1 ][ 3 ] ][ transaction_with_max_latency[ 1 ][ 4 ] ][ 1 ][ 1 ], streams[ transaction_with_max_latency[ 1 ][ 3 ] ][ transaction_with_max_latency[ 1 ][ 4 ] ][ 1 ][ 2 ] ) )
	print( " latency min     : " .. string.format( "%.3f [ tcp_stream # %d seqnum # %d | submit_sm-resp : frame # %d rel_time = %.3f --> submit_sm : frame # %d rel_time = %.3f ]", latency_min, transaction_with_min_latency[ 1 ][ 3 ], transaction_with_min_latency[ 1 ][ 4 ], transaction_with_min_latency[ 1 ][ 1 ], transaction_with_min_latency[ 1 ][ 2 ], streams[ transaction_with_min_latency[ 1 ][ 3 ] ][ transaction_with_min_latency[ 1 ][ 4 ] ][ 1 ][ 1 ], streams[ transaction_with_min_latency[ 1 ][ 3 ] ][ transaction_with_min_latency[ 1 ][ 4 ] ][ 1 ][ 2 ] ) )
	
	save_transactions_latency()

	-- "latency" graph : "max" value.
	local latency_max = math.ceil( latency_max ) 
	-- "latency" graph : "min" value.
	local latency_min = math.floor( latency_min )
	-- "latency" graph : "number of intervals".
	local latency_intervals = latency_max * 10	
	-- "latency" graph : "interval width".
	local latency_width =  ( latency_max - latency_min ) / latency_intervals
	
	local latency_xtics = 0.5
	if latency_max - latency_min <= 2.0 then
		latency_xtics = 0.2
	end
	
	-- weight with inverse of number of data points for normalization. 
	local weight = 1.0 / #transactions                 

	print( "" )
	print( "graphs" )
	print( "=============" )
	print( "" )
	print( " processing graph # 1 : " .. histogram_latency_title )
	print( " processing graph # 2 : " .. latency_title )
		
	save_gnuplot_script( gnuplot_executable .. " -persist -e \"reset \z	
							n = " .. latency_intervals .. " ; \z
							max = " .. latency_max .. " ; \z
							min = " .. latency_min .. " ; \z
							width = " .. latency_width .. " ; \z
							hist( x, width ) = width * floor( ( x + width / 2 ) / width ) ; \z	
							set term wxt 0 position 100 , 100 ; \z
							set term wxt 0 size 1200 , 480 ; \z
							set key top right ; \z
							set xrange [ min : max ] ; \z
							set yrange [ 0 : ] ; \z		
							set y2range [ 0 : 1 ] ; \z	
							set xtics min, " .. latency_xtics .. " , max ; \z
							set xtics font ', 7' ; \z
							set y2tics 0, 0.1 , 1 ; \z
							set boxwidth width * 0.9 ; 	\z
							set style fill solid 0.5 ; \z
							set ytics nomirror ; \z
							set y2tics nomirror ; \z
							set tics out nomirror ; \z
							set autoscale y ; \z														
							set xlabel '" .. latency_label .. "' ; \z
							set ylabel '" .. frequency_distribution_label .. "' ; \z	
							set y2label '" .. cumulative_distribution_label .. "' ; \z	
							set title '" .. histogram_latency_title .. "' ; \z
							set term wxt title '" .. window_title .. "' ; \z
							set grid ytics lc rgb '#bbbbbb' lw 1 lt 0 ; \z
							set grid xtics lc rgb '#bbbbbb' lw 1 lt 0 ; \z							
							plot '" .. latency_data .. "'  u ( hist( \\$2, width ) ):(1.0) smooth frequency w boxes lc rgb 'green' lt 1 lw 0.5 t 'frequency distribution' axes x1y1, '' u 2:(" .. weight .. ") smooth cumulative lc rgb 'red' t 'cumulative distribution' axes x1y2 ; \z	
							max = " .. math.ceil( time_relative_of_last_completed_transaction ) .. " ; \z
							min = " .. math.floor( time_relative_of_first_completed_transaction ) .. " ; \z							
							set term wxt 1 position 300 , 300; \z	
							reset ; \z
							set xrange [ min : max ] ; \z
							set yrange [ 0 : ] ; \z	
							set ytics nomirror ; \z							
							set tics out nomirror ; \z
							set autoscale y ; \z														
							set xlabel '" .. time_label .. "' ; \z
							set ylabel '" .. latency_label .. "' ; \z	
							set title '" .. latency_title .. "' ; \z
							set term wxt title '" .. window_title .. "' ; \z
							set grid ytics lc rgb '#bbbbbb' lw 1 lt 0 ; \z
							set grid xtics lc rgb '#bbbbbb' lw 1 lt 0 ; \z
							set style fill transparent solid 0.65 noborder ; \z							
							plot '" .. latency_data .. "' with filledcurves x1 lt 1 lc rgb 'blueviolet' notitle \" ; \z
							rm -f " .. latency_data .. " ; \z
							rm -f " .. gnuplot_script )
							
end

-----------------------------------------------------------------------------------------------------------------------------
-- This function will get called at the end of the "capture" to print the summary.
 
 function tcp_tap.draw()
     -- do nothing.
 end

-----------------------------------------------------------------------------------------------------------------------------
-- This function will be called at the end of the "capture" run.

function smpp_tap.reset()

    -- clear/destroy tables at the end of the file.
	streams = nil
	transactions = nil
	
end
 
-----------------------------------------------------------------------------------------------------------------------------
-- This function will be called at the end of the "capture" run.

function tcp_tap.reset()
    -- do nothing.
end
 
-----------------------------------------------------------------------------------------------------------------------------

--   54   0.204  5 0x00000004 13885
--  117   0.456  5 0x80000004 13885

-- #submit_sm) -- 8811
-- submit_sm_resp) -- 8702  17513
--2238
--2233
--2243
--2087
--2115
--2135
--2221
--2241

-- ack 7128 x 2 = 14256
-- non ack 3526    17512
-- 0x80000004 1574
-- 0x00000004 1682 10384
-- 1.099096801	0.273	2.088337324	8.912	0.174

--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && tcp.stream == 13 && smpp.sequence_number == 13903
--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && (tcp.stream == 13) && (smpp.sequence_number == 13903) 1.45
--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && (tcp.stream == 9) && (smpp.sequence_number == 13901) 0.30
--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && (tcp.stream == 4) && (smpp.sequence_number == 15118) 0.18
--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && (tcp.stream == 9) && (smpp.sequence_number == 15587) 0.17
--((smpp.command_status == 0x00000000 && smpp.command_id == 0x80000004) || (smpp.command_id == 0x00000004)) && (tcp.stream == 9) && (smpp.sequence_number == 15586) 0.38


