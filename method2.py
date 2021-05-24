# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from operator import attrgetter
from ryu.lib import hub
import os
from datetime import datetime
import re



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tenant = self._init_tenant()

    def _init_tenant(self):
        tenant = {}
        tenant[9] = 1
        tenant[12] = 1
        tenant[15] = 1
        tenant[3] = 1
        tenant[6] = 1

        tenant[10] = 2
        tenant[13] = 2
        tenant[16] = 2
        tenant[4] = 2
        tenant[1] = 2
        tenant[7] = 2

        tenant[11] = 3
        tenant[14] = 3
        tenant[2] = 3
        tenant[5] = 3
        tenant[8] = 3

        return tenant

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # When a switch is add to the controller, this function will be run.
    # Add a catch-all flow entry, let the switch can send packet to controller.
    def switch_features_handler(self, ev):
        # print("switch features handler")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # self.logger.info(f"*********************************")
        # self.logger.info("add flow")
        # self.logger.info(f"datapath, {datapath}")
        # self.logger.info(f"priority, {priority}")
        # self.logger.info(f"match, {match}")
        # self.logger.info(f"actions, {actions}")
        # self.logger.info(f"*********************************")

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        
        # buffer_id: the buffer id on OpenFlow switch
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        # 1. Extract vital informations about the message.
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        # 2. Learn the MAC address and port.
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        src_int = self._mac_to_int(src)
        dst_int = self._mac_to_int(dst)
        broadcast_int = self._mac_to_int("ff:ff:ff:ff:ff:ff")
        try:
            if self.tenant[src_int] != self.tenant[dst_int]:
                return
        except:
            pass
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        out_ports = []
        out_port = None
        # 3. Look-up destination.
        if dst_int == broadcast_int:
            target_tnt = self.tenant[src_int]
            for try_dst in self.mac_to_port[dpid]:
                try:
                    if self.tenant[self._mac_to_int(try_dst)] == target_tnt and try_dst != src:
                        the_out_port = self.mac_to_port[dpid][try_dst]
                        if the_out_port != in_port and (the_out_port not in out_ports):
                            out_ports.append(the_out_port)

                except:
                    pass
        elif dst in self.mac_to_port[dpid]:
            out_ports.append(self.mac_to_port[dpid][dst])      

        else:
            out_port = ofproto.OFPP_FLOOD
            out_ports.append(ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port) for out_port in out_ports]

        # 4. Add flow. Next time the switch won't need to bother the controller
        #    when receiving a frame from the same pair of source and destination.
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # 5. Forward the frame.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Monitor part
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                # print(f"{datapath.id}:{datapath}")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            now = datetime.now()
            print(f'Current Time: {now.strftime("%H:%M:%S")}')
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)
            # os.system('clear')

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath         '
        #                  'in-port  eth-dst           '
        #                  'out-port packets  bytes')
        # self.logger.info('---------------- '
        #                  '-------- ----------------- '
        #                  '-------- -------- --------')
        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                      flow.match['eth_dst'])):
        #     self.logger.info('%016x %8x %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['in_port'], stat.match['eth_dst'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('****************************')
        self.logger.info('Switch ID: %2d', ev.msg.datapath.id)
        self.logger.info('Port No  Tx-Bytes  Rx-Bytes')
        self.logger.info('-------  --------  --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%8x %8d %8d',
                             stat.port_no,
                             stat.rx_packets,
                             stat.tx_packets)
        self.logger.info('MAC Address Table   Port No')
        for dpid in self.mac_to_port:
            if int(dpid) == ev.msg.datapath.id:
                tbl = self.mac_to_port[dpid]
                for key in tbl:
                    self.logger.info('%s         %d',
                                     key, tbl[key])
        self.logger.info('****************************')
        #self.logger.info('---------------------------')

        #self.logger.info('%s                        %d',
        #                 )
        
        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        # for stat in sorted(body, key=attrgetter('port_no')):
        #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
        #                      ev.msg.datapath.id, stat.port_no,
        #                      stat.rx_packets, stat.rx_bytes, stat.rx_errors,
        #                      stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    def _mac_to_int(self, mac):
        res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
        if res is None:
            raise ValueError('invalid mac address')
        return int(res.group(0).replace(':', ''), 16)

    def _int_to_mac(self, macint):
        if type(macint) != int:
            raise ValueError('invalid integer')
        return ':'.join(['{}{}'.format(a, b)
                        for a, b
                        in zip(*[iter('{:012x}'.format(macint))]*2)])