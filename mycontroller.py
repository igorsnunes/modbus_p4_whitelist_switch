#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def writeModbusWhitelistRules(p4info_helper, ingress_sw, dstIp, fcode, unit_id): 
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.whitelist_mbap_pkts_table",
        match_fields={
            "hdr.ipv4.dstAddr": dstIp, "hdr.mbap.fcode": fcode, "hdr.mbap.unit_id": unit_id
        },
        action_name="MyIngress.WhiteListAndCount",
        action_params={}
    )
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress mbap rule on %s" % ingress_sw.name


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )
def receivePacketFromDataPlane(sw):
    request = sw.StreamMessageRequest()
    
    # Create request list via self.packet_out_msg
    # print (debug)
 
    # using self.requests_stream.put() to append request
 
    # Get response from self.stream_msg_resp 
    # print out packet_out ()
    
    for response in self.stream_msg_resp:
        if response.WhichOneof("update") is "packet":
            print("=============================================================")
            print("Received packet-in payload %s" % (response.packet.payload))
            print("Received packet-in metadata: ")
            for metadata in response.packet.metadata: 
                # uint32
                print("\tmetadata id: %s" %s (metadata.metadata_id))
                # bytes
                print("\tmetadata value: %s" %s (metadata.value))
            print("=============================================================")

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        #s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        # TODO Uncomment the following two lines to read table entries from s1 and s2
        readTableRules(p4info_helper, s1)

        writeModbusWhitelistRules(p4info_helper, ingress_sw=s1, dstIp="10.0.2.2", fcode=0x0, unit_id=0x0) 
        writeModbusWhitelistRules(p4info_helper, ingress_sw=s1, dstIp="10.0.1.1", fcode=0x0, unit_id=0x0) 

        writeModbusWhitelistRules(p4info_helper, ingress_sw=s1, dstIp="10.0.3.3", fcode=0x0, unit_id=0x0) 
 
        # Print the tunnel counters every 2 seconds
        while True:
            sleep(2)
            #print '\n----- Reading tunnel counters -----'
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterHit", 0)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterHit", 1)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterHit", 2)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterHit", 3)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterDrop", 0)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterDrop", 1)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterDrop", 2)
            printCounter(p4info_helper, s1, "MyIngress.ingressMbapCounterDrop", 3)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mbus_switch.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mbus_switch.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
