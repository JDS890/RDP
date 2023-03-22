#!/usr/bin/env python3

# Project: P2 CSC361
# Student: Joshua Stein
# Student number: V00951354

# Example usage:
# Restart echo server on R immediately before running this script: `cat fifo | tee fifo_input | nc -u -l -p 8888 | tee fifo`
# Add delay and loss on R: `qdisc change dev r-eth1 root netem delay 101ms loss 25%`
# Prepare packet trace on R's r-eth1 interface: `tcpdump -n -l -i r-eth1 udp port 8888 -w 500kb_test.pcap`
# Send file: `python3 rdp.py 192.168.1.100 10000 file.pdf file.pdf` 

import sys
import re
import socket
import select
import datetime
import random
from collections import deque

# Debug logging
DLOG = False # ToDo: False for submission

# RDP spec logging
LOG = True  # ToDo: True for submission

# On Lab computer
LAB = True  # ToDo: True for submission

H1_IP = '192.168.1.100'
H2_IP = '10.10.1.100'
ECHO_ADDR = (H2_IP if LAB else 'localhost', 8888)

MAC_OS_NETCAT_UDP_BUFFER_MAX = 1024
LINUX_OS_NETCAT_UDP_BUFFER_MAX = 8192
UDP_PAYLOAD_MAX_SIZE = LINUX_OS_NETCAT_UDP_BUFFER_MAX if LAB else MAC_OS_NETCAT_UDP_BUFFER_MAX

RDP_PAYLOAD_MAX_SIZE = 1024 if LAB else 512
(SYN, DAT, FIN, ACK, RST) = range(5)
CMD_S = {SYN, DAT, FIN, RST}
CMD_R = {ACK, RST}
CMD = { SYN: 'SYN', DAT: 'DAT', FIN: 'FIN', ACK: 'ACK', RST: 'RST' }
CMD_REV = { CMD[x]: x for x in CMD }

H_SEQ = 'Sequence'
H_ACK = 'Acknowledgement' # Assuming spec's 'Acknowledgment' is a typo...
H_LEN = 'Length'
H_WIN = 'Window'
HEADERS = {H_SEQ, H_ACK, H_LEN, H_WIN}

VALID_RDPPACKET_METADATA = re.compile(r'(?P<command>(?:SYN)|(?:DAT)|(?:FIN)|(?:ACK)|(?:RST))\n(?P<headerlines>(?:[A-Z][a-z]+: (?:(?:-1)|[0-9]+)\n)*)\n', flags=re.DOTALL)
VALID_RDPPACKET_HEADERLINES = re.compile(r'(?P<fieldname>[A-Z][a-z]+): (?P<fieldvalue>(?:(?:-1)|[0-9]+))\n')

SENDER_RETRANSMISSION_TIME = 0.5
DUPLICATE_ACK_THRESHOLD = 3
RECEIVER_BUFFER_SIZE = 2 * RDP_PAYLOAD_MAX_SIZE
SENDER_FIN_THRESHOLD = 5


class Message:
    ''' Abstraction of the RdpPacket described in the RDP spec
    '''

    def __init__(
            self,
            command: int,
            payload=None,
            headers={} # dict
        ):

        self.command = command
        self.payload = payload

        self.sequence = headers.get(H_SEQ)
        self.acknowledgement = headers.get(H_ACK)
        self.length = headers.get(H_LEN)
        self.window = headers.get(H_WIN)
        
    
    def __str__(self):
        if self.command in {SYN, DAT, FIN}:
            return f"{CMD[self.command]}; {H_SEQ}: {self.sequence}; {H_LEN}: {self.length}"
        elif self.command == ACK:
            return f"{CMD[self.command]}; {H_ACK}: {self.acknowledgement}; {H_WIN}: {self.window}"
        elif self.command == RST:
            return f"{CMD[self.command]}" + (f"; {H_ACK}: {self.acknowledgement}" if self.acknowledgement else "")
    
    def __repr__(self):
        return f"command: {self.command}, payload: {None if self.payload == None else bool(self.payload)}, sequence: {self.sequence}, acknowledgement: {self.acknowledgement}, length: {self.length}, window: {self.window}"

    def pack(self):
        if not self.isvalid():
            dlog(assertion=f"Refuse to pack invalid message, returning empty bytes object instead", error=True)
            return b''
        if self.command in {SYN, FIN}:
            return f"{CMD[self.command]}\n{H_SEQ}: {self.sequence}\n{H_LEN}: {self.length}\n\n".encode()
        elif self.command == DAT:
            return f"{CMD[self.command]}\n{H_SEQ}: {self.sequence}\n{H_LEN}: {self.length}\n\n".encode() + self.payload
        elif self.command == ACK:
            return f"{CMD[self.command]}\n{H_ACK}: {self.acknowledgement}\n{H_WIN}: {self.window}\n\n".encode()
        elif self.command == RST:
            # Note: RST packet has ACK field iff RST originated from sender
            ack_headerline = f"{H_ACK}: {self.acknowledgement}\n" if self.acknowledgement != None else ''
            return f"{CMD[self.command]}\n{ack_headerline}\n".encode()
    
    def isvalid(self):
        if self.command in {SYN, FIN}:
            return (self.sequence != None
                    and self.sequence >= 0
                    and self.length == 0
                    and self.payload == None
                    and (self.acknowledgement == None or self.acknowledgement == -1)
                    and (self.window == None or self.window == -1))
        elif self.command == DAT:
            return (self.sequence != None
                    and self.sequence > 0
                    and self.payload != None
                    and len(self.payload) in range(1, RDP_PAYLOAD_MAX_SIZE + 1)
                    and self.length == len(self.payload)
                    and (self.acknowledgement == None or self.acknowledgement == -1)
                    and (self.window == None or self.window == -1))
        elif self.command == ACK:
            return (self.acknowledgement != None
                    and self.acknowledgement >= 0
                    and self.window != None
                    and self.window >= 0
                    and (self.sequence == None or self.sequence == -1)
                    and (self.length == None or self.length == 0)
                    and self.payload == None)
        elif self.command == RST:
            return ((self.sequence == None or self.sequence >= 0)
                    and (self.acknowledgement == None or self.acknowledgement >= 0)
                    and (self.length == None or self.length == 0)
                    and (self.window == None or self.window == -1)
                    and self.payload == None)
        else:
            dlog(assertion=f"Unexpected command in message {self.__repr__}", error=True)
            return False


class Sender:
    ''' Anticipate packet loss
    '''
    
    states = {'CLOSED', 'CLOSING', 'OPEN'}
    retransmission_time_delta = datetime.timedelta(seconds=SENDER_RETRANSMISSION_TIME)
    isn = random.randrange(2**32)

    def __init__(self, filename):
        self._filename = filename
        self._state = 'CLOSED'
        self._message_queue = deque()

        # Window dimensions
        self._receiver_window_width = None
        self._receiver_window_base = None
        self._rdp_payload_width = None # at most half the _receiver_window_width
        
        # File parameters
        self._file_buffer = [] # File buffered into chunks or size _rdp_payload_width
        self._file_size = 0
        self._final_ack_number = 0 # If sequence number begins at 1, set to filesize + 1

        # Variables for retransmission
        self._window_base_ack_counter = 0
        self._timer = datetime.datetime.now() - self.retransmission_time_delta

        self._sent_seqnums = set()
        self._fin_count = 0
    
    def enque(self, message):
        self._message_queue.append(message)
    
    def _window_base_timer_expire(self):
        self._timer = self._timer - self.retransmission_time_delta

    def _window_base_timer_expired(self):
        return datetime.datetime.now() - self._timer > self.retransmission_time_delta
    
    def _window_base_timer_reset(self):
        self._timer = datetime.datetime.now()
    
    def _window_base_ack_count_expired(self):
        return self._window_base_ack_counter >= DUPLICATE_ACK_THRESHOLD
    
    def _window_base_ack_count_reset(self):
        self._window_base_ack_counter = 0
    
    def process(self):

        to_receiver = deque()
        sender_active = True

        if self._state == 'CLOSED':

            if self._window_base_timer_expired():
                self._window_base_timer_reset()
                to_receiver.append(Message(SYN, headers={H_SEQ: self.isn, H_LEN: 0}))

            # Process all messages
            while (self._message_queue):

                message = self._message_queue.popleft()

                if not message.isvalid():
                    to_receiver.append(Message(RST, headers={H_ACK: 1}))

                elif message.command == ACK and message.acknowledgement != (self.isn + 1):
                    to_receiver.append(Message(RST, headers={H_ACK: 1}))

                elif message.command == ACK:
                    log(message, send=False)
                    self._state = 'OPEN'
                    self._window_base_timer_expire()

                    assert(message.acknowledgement == self.isn + 1)
                    
                    self._init_filestream(message.window)
                    break

                # Ignore RSTs

        if self._state == 'OPEN':
            
            # Get all incoming acknowledgements
            ack_seqnums_counts = {}
            while (self._message_queue):
                message = self._message_queue.popleft()

                if not message.isvalid():
                    to_receiver.append(Message(RST, headers={H_ACK: 1}))
                
                elif message.command == ACK:
                    log(message, send=False)
                    ack_seqnum = message.acknowledgement
                    if ack_seqnum in ack_seqnums_counts:
                        ack_seqnums_counts[ack_seqnum] += 1
                    else:
                        ack_seqnums_counts[ack_seqnum] = 1
            
            received_ack_seqnums = set(ack_seqnums_counts)
            valid_ack_seqnums = self._valid_ack_seqnums()
            invalid_received_ack_seqnums = received_ack_seqnums.difference(valid_ack_seqnums)
            if invalid_received_ack_seqnums:
                dlog(assertion=f"Sender recieved unexpected seqnum acknowledgements: {invalid_received_ack_seqnums}", error=True)
            valid_received_ack_seqnums = received_ack_seqnums.intersection(valid_ack_seqnums)
            largest_received_ack_seqnum = max(valid_received_ack_seqnums) if valid_received_ack_seqnums else None
            
            if largest_received_ack_seqnum != None: dlog(assertion=f"largest seqnum = {largest_received_ack_seqnum}")

            if largest_received_ack_seqnum == self._final_ack_number:
                self._state = 'CLOSING'
                to_receiver.append(Message(FIN, headers={H_SEQ: self._final_ack_number, H_LEN: 0}))
                self._fin_count += 1
                self._window_base_timer_reset()

            elif largest_received_ack_seqnum == None or largest_received_ack_seqnum <= self._receiver_window_base:
                if largest_received_ack_seqnum == self._receiver_window_base:
                    self._window_base_ack_counter += 1

                # Retransmission
                if self._window_base_ack_count_expired() or self._window_base_timer_expired():
                    self._window_base_ack_count_reset()
                    self._window_base_timer_reset()
                    # GBN implementation
                    seqnums_to_send = self._valid_seqnums()
                    to_receiver.extend(self._build_dat_messages_from_seqnums(seqnums_to_send))
                    self._sent_seqnums = seqnums_to_send
            
            else:
                assert(largest_received_ack_seqnum > self._receiver_window_base)
                self._receiver_window_base = largest_received_ack_seqnum
                self._window_base_ack_counter = ack_seqnums_counts[largest_received_ack_seqnum]
                self._window_base_timer_reset()
                self._sent_seqnums = {x for x in self._sent_seqnums if x >= largest_received_ack_seqnum}

        if self._state == 'CLOSING':
            while (self._message_queue):
                message = self._message_queue.popleft()

                if not message.isvalid():
                    to_receiver.append(Message(RST, headers={H_ACK: 1}))
                
                elif message.command == ACK:
                    log(message, send=False)
                    if message.acknowledgement == self._final_ack_number:
                        self._state = 'CLOSED'
                        sender_active = False
                        break
                    else:
                        to_receiver.append(Message(RST, headers={H_ACK: 1}))
            
            # Wait for response from receiver before closing completely
            if self._state == 'CLOSING' and self._window_base_timer_expired():
                if self._fin_count >= SENDER_FIN_THRESHOLD:
                    self._state = 'CLOSED'
                    sender_active = False
                else:
                    to_receiver.append(Message(FIN, headers={H_SEQ: self._final_ack_number, H_LEN: 0}))
                    self._window_base_timer_reset()
                    self._fin_count += 1

        return to_receiver, sender_active

    def _init_filestream(self, window_width):

        self._receiver_window_width = window_width
        self._receiver_window_base = 1
        self._rdp_payload_width = min(self._receiver_window_width // 2, RDP_PAYLOAD_MAX_SIZE)

        self._file_buffer.clear()
        with open(self._filename, 'rb') as file:
            while (line := file.read(self._rdp_payload_width)):
                self._file_buffer.append(line)
        self._file_size = (len(self._file_buffer)-1) * self._rdp_payload_width + len(self._file_buffer[-1])
        self._final_ack_number = self._file_size + 1
        dlog(assertion=f"File size: {self._file_size} bytes")


    def _valid_ack_seqnums(self):
        ''' Return set of sequence numbers which can be expected from
        the receiver given the current window base, the window width.
        '''
        valid_ack_seqnums = {i for i in range(self._receiver_window_base, min(self._receiver_window_base + self._receiver_window_width + 1, self._final_ack_number + 1), self._rdp_payload_width)}
        if (len(valid_ack_seqnums) <= 2):
            valid_ack_seqnums.add(self._final_ack_number)
        return valid_ack_seqnums
    
    def _valid_seqnums(self):
        ''' Return the set of seqence numbers which could start a payload sent to the receiver
        '''
        return {i for i in range(self._receiver_window_base, min(self._receiver_window_base + self._rdp_payload_width + 1, self._final_ack_number), self._rdp_payload_width)}

    def _build_dat_messages_from_seqnums(self, seqnums):
        messages = []
        for seqnum in seqnums:
            assert(((seqnum - 1) % self._rdp_payload_width) == 0)
            buffer_index = (seqnum - 1) // self._rdp_payload_width
            rdp_payload = self._file_buffer[buffer_index]
            messages.append(Message(DAT, headers={H_SEQ: seqnum, H_LEN: len(rdp_payload)}, payload=rdp_payload))
        return messages


class Receiver:
    ''' Anticipate out-of-order segments, lost acknowledgements, repeated SNs.
    '''

    states = {'CLOSED', 'CLOSING', 'OPEN'}

    def __init__(self, filename):
        self._filename = filename
        
        # Accommodate exactly two payloads
        # Expect all but the last payload to be exactly RDP_PAYLOAD_MAX_SIZE bytes
        self._window_size = 2 * RDP_PAYLOAD_MAX_SIZE
        
        self._window_base = 1 # Assume sender starts from 1
        self._state = 'CLOSED'
        self._message_queue = deque()
        self._sender_isn = None
        self._file_buffer = []
        self.window = bytearray(self._window_size)
        self._window_range_low = None
        self._window_range_high = None

    def enque(self, message):
        self._message_queue.append(message)
    
    def process(self):

        to_sender = deque()
        receiver_active = True

        if self._state == 'CLOSED':
            
            # Expect a SYN packet
            while self._message_queue:
                message = self._message_queue.popleft()
                if not message.isvalid() or message.command != SYN:
                    to_sender.append(Message(RST, headers={H_ACK: 1}))
                else:
                    log(message, send=False)
                    # Be prepared to reacknowledge this
                    self._sender_isn = message.sequence
                    to_sender.append(Message(ACK, headers={H_ACK: self._sender_isn+1, H_WIN: self._window_size}))
                    self._state = 'OPEN'
        
        if self._state == 'OPEN':
            while self._message_queue:
                message = self._message_queue.popleft()
                
                if not message.isvalid():
                    to_sender.append(Message(RST, headers={H_ACK: 1}))
                
                elif message.command == SYN:
                    log(message, send=False)
                    self._sender_isn = message.sequence
                    to_sender.append(Message(ACK, headers={H_ACK: self._sender_isn+1, H_WIN: self._window_size}))

                elif message.command == FIN:
                    log(message, send=False)
                    to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
                    with open(self._filename, 'wb') as file:
                        for line in self._file_buffer:
                            file.write(line)
                    self._state = 'CLOSED'
                    receiver_active = False
                    break

                elif message.command == DAT:
                    log(message, send=False)

                    if message.sequence < self._window_base:
                        to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
                        dlog(assertion="Immediately ACKed lower SN")

                    elif message.sequence == self._window_base:
                        assert(not (self._window_range_high and self._window_range_low))

                        if self._window_range_low:
                            # This may be the last packet in the payload, so let's not be stubborn
                            # and wait for another packet, because there might not be one.
                            dlog(assertion="SN LOW-COLLISION, sliding window")
                            assert(self._slide_window(to_sender))
                        
                        elif self._window_range_high:
                            # This should complete the buffer.
                            dlog(assertion="SN LOW-COMPLETE, sliding window")
                            self._window_range_low = range(self._window_base, self._window_base + message.length)
                            self._write_to_buffer(self.window, message.payload, 0)
                            assert(self._slide_window(to_sender))
                            
                        
                        else:
                            # This is the case where we delay acknowledgement to save packets.
                            dlog(assertion="SN LOW-FILL, withholding acknowledgement")
                            self._window_range_low = range(self._window_base, self._window_base + message.length)
                            self._write_to_buffer(self.window, message.payload, 0)
                    
                    elif message.sequence == self._window_base + RDP_PAYLOAD_MAX_SIZE:
                        assert(not (self._window_range_high and self._window_range_low))

                        if self._window_range_low:
                            # Completes the buffer
                            dlog(assertion="SN HIGH-COMPLETE, sliding window")
                            self._window_range_high = range(message.sequence, message.sequence + message.length)
                            self._write_to_buffer(self.window, message.payload, RDP_PAYLOAD_MAX_SIZE)
                            assert(self._slide_window(to_sender))
                        
                        elif self._window_range_high:
                            # We already have this packet. We send acknowledgement but can't slide
                            dlog(assertion="SN HIGH-COLLISION, re-acknowledging")
                            to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
                        
                        else:
                            # Buffer is empty. We write the higher packet and acknowledge the packet, we but can't slide.
                            dlog(assertion="SN HIGH-FILL, re-acknowledging")
                            self._window_range_high = range(message.sequence, message.sequence + message.length)
                            self._write_to_buffer(self.window, message.payload, RDP_PAYLOAD_MAX_SIZE)
                            to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
                    
                    else:
                        dlog(assertion=f"UNEXPECTED SN! Ignoring DAT packet with badly align seq number (not at start or mid of window)", error=True)
                        to_sender.append(Message(RST))      


        return to_sender, receiver_active
    
    def _write_to_buffer(self, buffer, new_bytes, start_index):
        assert(start_index + len(new_bytes) <= len(buffer))
        buffer[start_index: start_index + len(new_bytes)] = new_bytes
    
    def _slide_window(self, to_sender):
        ''' Return True iff window slide is valid and successful
        '''
        if not self._window_range_low:
            return False
        if not self._window_range_high:
            self._window_base = self._window_range_low.stop
            self._file_buffer.append(self.window[0 : len(self._window_range_low)])
            to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
            self._window_range_low = None # Clean up
            return True
        if self._window_range_low.stop != self._window_range_high.start:
            dlog(assertion=f"Unaligned lower and upper window", error=True)
            return False
        
        self._window_base = self._window_range_high.stop
        self._file_buffer.append(self.window[0 : len(self._window_range_low) + len(self._window_range_high)])
        to_sender.append(Message(ACK, headers={H_ACK: self._window_base, H_WIN: self._window_size}))
        self._window_range_low = None # Clean up
        self._window_range_high = None
        return True


def rdp_run(rdp_address, read_filename, write_filename):

    rdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create UDP socket
    rdp.bind(rdp_address)
    rdp.setblocking(False)

    sender = Sender(read_filename)
    receiver = Receiver(write_filename)

    sender_active = True
    receiver_active = True
    to_receiver = None
    to_sender = None
    rdp_packet_q = deque()

    
    while sender_active or receiver_active:
        while rdp_is_readable(rdp):
            udp_payload_bin, _ = rdp.recvfrom(UDP_PAYLOAD_MAX_SIZE)
            payload_to_messages(udp_payload_bin, sender, receiver)

        if sender_active:
            to_receiver, sender_active = sender.process()
            
        if receiver_active:
            to_sender, receiver_active = receiver.process()
        
        while to_receiver or to_sender:
            if to_receiver:
                message = to_receiver.popleft()
                rdp_packet = message.pack()
                if rdp_packet:
                    log(message, send=True)
                    rdp_packet_q.append(rdp_packet)
            
            if to_sender:
                message = to_sender.popleft()
                rdp_packet = message.pack()
                if rdp_packet:
                    log(message, send=True)
                    rdp_packet_q.append(rdp_packet)
        
        send_pooled(rdp, rdp_packet_q)


def send_pooled(rdp, rdp_packet_q):
    ''' Pool consecutive, small RDP packets and send in one UDP payload
    '''
    
    while rdp_is_writable(rdp) and rdp_packet_q:
        pool_size = 0
        pool_members = []
        
        # Fill up pool
        while rdp_packet_q:
            new_member = rdp_packet_q.popleft()
            if len(new_member) + pool_size > UDP_PAYLOAD_MAX_SIZE:
                rdp_packet_q.appendleft(new_member)
                break
            pool_members.append(new_member)
            pool_size += len(new_member)
        
        if not pool_members:
            dlog(assertion=f"Single RDP packet is wider ({len(udp_payload)} bytes) than UDP_PAYLOAD_MAX_SIZE ({UDP_PAYLOAD_MAX_SIZE})! Dropped packet.", error=True)
            assert(pool_members)
            
        udp_payload = b''.join(pool_members)
        udp_payload_size = len(udp_payload)
        bytes_sent_last = rdp.sendto(udp_payload, ECHO_ADDR)
        bytes_sent_total = bytes_sent_last if bytes_sent_last > 0 else 0
        send_count = 1
        while (bytes_sent_last > 0 and bytes_sent_total < udp_payload_size and rdp_is_writable(rdp)):
            udp_payload = udp_payload[bytes_sent_last:]
            bytes_sent_last = rdp.sendto(udp_payload, ECHO_ADDR)
            send_count += 1
            if bytes_sent_last > 0: bytes_sent_total += bytes_sent_last
        
        if send_count > 1 or bytes_sent_total < udp_payload_size:
            dlog(assertion=f"Sent {bytes_sent_total}/{udp_payload_size} of UDP payload containing {len(pool_members) if pool_members else 1} messages in {send_count} sends", error=True)


def payload_to_messages(udp_payload: bytes, sender, receiver):
    ''' Extract RDP packets from udp_payload, create Message from each
    extracted RDP packet, enque Message to sender or receiver
    '''

    metadata_separator = b'\n\n'
    separator_pos = udp_payload.find(metadata_separator)
    byte_meta_start = 0

    while (separator_pos > -1):
        byte_meta_end = separator_pos + len(metadata_separator)

        # If can't convert metadata to utf-8, quietly drop payload and return.
        try:
            metadata = udp_payload[byte_meta_start: byte_meta_end].decode()
        except UnicodeDecodeError:
            dlog(assertion=f"Failed to decode RDP metadata, dropped payload at byte {byte_meta_start}/{len(udp_payload)}", error=True)
            return
        
        # If metadata in wrong form, quietly drop payload and return.
        metadata_match = VALID_RDPPACKET_METADATA.fullmatch(metadata)
        if not metadata_match:
            dlog(assertion=f"Failed to interpret RDP metadata, dropped payload at byte {byte_meta_start}/{len(udp_payload)}", error=True)
            return
        
        packet_headerlines = VALID_RDPPACKET_HEADERLINES.findall(metadata_match.group('headerlines'))
        packet_headers = {x[0] : int(x[1]) for x in packet_headerlines}
        command = CMD_REV[metadata_match.group('command')]

        payload_length = 0
        if H_LEN in packet_headers and packet_headers[H_LEN] > 0:
            payload_length = packet_headers[H_LEN]
        
        # If not enough bytes remain in payload, quietly drop payload and return.
        if byte_meta_end + payload_length > len(udp_payload):
            dlog(assertion=f"Failed to extract RDP payload, {byte_meta_end} + {payload_length} > {len(udp_payload)}, dropped payload at byte {byte_meta_start}/{len(udp_payload)}", error=True)
            return
        
        # Enqueue new message with payload if necessary
        destination = receiver if is_from_sender(command, packet_headers) else sender
        if payload_length:
            destination.enque(Message(command, headers=packet_headers, payload=udp_payload[byte_meta_end: byte_meta_end+payload_length]))
        else:
            destination.enque(Message(command, headers=packet_headers))
        
        byte_meta_start = byte_meta_end + payload_length
        separator_pos = udp_payload.find(metadata_separator, byte_meta_start)
    
    if byte_meta_start < len(udp_payload):
        dlog(assertion=f"Failed to recognise RDP payload trail, dropped payload at byte {byte_meta_start}/{len(udp_payload)}", error=True)


def rdp_is_writable(rdp):
    _, wlist, _ = select.select([rdp], [rdp], [rdp], 1.0)
    return rdp in wlist


def rdp_is_readable(rdp):
    rlist, _, _ = select.select([rdp], [rdp], [rdp], 1.0)
    return rdp in rlist


def log(message, send=True):
    if not LOG: return
    now = datetime.datetime.now()
    formatted_time = now.strftime(f"%a %b %d %H:%M:%S {now.astimezone().tzinfo} %Y")
    print(f"{formatted_time}: {'Send' if send else 'Receive'}; {message}", flush=True)


def dlog(message=None, assertion=None, action=None, reason=None, error=False):
    if not DLOG: return
    if action:
        print(f"DEBUG{' (ERROR!)' if error else ''}; ACTION: {action}; REASON: {reason}", flush=True)
    elif assertion:
        print(f"DEBUG{' (ERROR!)' if error else ''}; ASSERTION: {assertion}", flush=True)
    else:    
        print(f"DEBUG{' (ERROR!)' if error else ''}: {message}", flush=True)


def is_from_sender(command, headers):
    return (command in {SYN, DAT, FIN}) or (command == RST and H_ACK in headers)


def main():
    if (len(sys.argv) != 5):
        print("Usage: python3 rdp.py [ip_address] [port_number] [read_filename] [write_filename]\n", file=sys.stderr)
        sys.exit(1)
    
    
    rdp_address = (sys.argv[1], int(sys.argv[2]))  
    rdp_run(rdp_address, sys.argv[3], sys.argv[4])


if __name__ == '__main__':
    main()
