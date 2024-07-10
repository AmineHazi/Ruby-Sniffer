require 'packetfu'
require 'json'

# Define the interface to sniff on
interface = ARGV[0] || PacketFu::Utils.default_interface

# Check if the interface is valid
unless interface
  puts "No valid interface found. Please provide a valid network interface."
  exit
end

# Array to store captured packets
packets = []

# Create a packet capture object
capture = PacketFu::Capture.new(iface: interface, start: true, promisc: true)

puts "Starting packet capture on #{interface}..."
puts "Press Ctrl+C to stop the capture and save the packets to captured_packets.json."

# Signal handler to stop the capture
Signal.trap("INT") do
  puts "\nStopping packet capture..."
  File.open('captured_packets.json', 'w') do |file|
    file.write(JSON.pretty_generate(packets))
  end
  puts "Packets saved to captured_packets.json."
  exit
end

def detect_protocol(packet_info)
  src_port = packet_info.dig(:tcp, :src_port) || packet_info.dig(:udp, :src_port)
  dst_port = packet_info.dig(:tcp, :dst_port) || packet_info.dig(:udp, :dst_port)

  case src_port || dst_port
  when 80 then 'HTTP'
  when 443 then 'HTTPS'
  when 21 then 'FTP'
  when 22 then 'SSH'
  when 23 then 'Telnet'
  when 25 then 'SMTP'
  when 110 then 'POP3'
  when 143 then 'IMAP'
  when 53 then 'DNS'
  else 'Unknown'
  end
end

# Capture packets until interrupted
capture.stream.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)

  # Basic packet information
  packet_info = {
    timestamp: Time.now,
    eth_src: packet.eth_saddr,
    eth_dst: packet.eth_daddr,
    eth_proto: packet.eth_proto
  }

  # Check if the packet has an IP header
  if packet.is_ip?
    packet_info[:ip] = {
      src_ip: packet.ip_saddr,
      dst_ip: packet.ip_daddr,
      ip_proto: packet.ip_proto,
      ip_id: packet.ip_id,
      ip_ttl: packet.ip_ttl,
      ip_len: packet.ip_len
    }

    # Add TCP-specific information if the packet is a TCP packet
    if packet.is_tcp?
      packet_info[:tcp] = {
        src_port: packet.tcp_sport,
        dst_port: packet.tcp_dport,
        seq_num: packet.tcp_seq,
        ack_num: packet.tcp_ack,
        tcp_flags: {
          urg: packet.tcp_flags.urg,
          ack: packet.tcp_flags.ack,
          psh: packet.tcp_flags.psh,
          rst: packet.tcp_flags.rst,
          syn: packet.tcp_flags.syn,
          fin: packet.tcp_flags.fin
        },
        window: packet.tcp_win,
        checksum: packet.tcp_sum,
        urgent_pointer: packet.tcp_urg
      }
    end

    # Add UDP-specific information if the packet is a UDP packet
    if packet.is_udp?
      packet_info[:udp] = {
        src_port: packet.udp_sport,
        dst_port: packet.udp_dport,
        len: packet.udp_len,
        checksum: packet.udp_sum
      }
    end

    # Add ICMP-specific information if the packet is an ICMP packet
    if packet.is_icmp?
      packet_info[:icmp] = {
        icmp_type: packet.icmp_type,
        icmp_code: packet.icmp_code,
        checksum: packet.icmp_sum,
        id: packet.icmp_id,
        seq: packet.icmp_seq
      }
    end
  end

  # Add protocol detection
  packet_info[:detected_protocol] = detect_protocol(packet_info)

  # Add packet payload
  packet_info[:payload] = packet.payload.unpack('H*').first

  # Add packet info to the array
  packets << packet_info

  # Print packet details to the console
  puts JSON.pretty_generate(packet_info)
end