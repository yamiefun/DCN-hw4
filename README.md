# DCN Project 4 Report

## Introduction
The purpose of this project is to implement multi-tenancy in data center network architecture.
A tenant is a group of users who share a common access with specific privileges to the software instance. With a multitenant architecture, a software application is designed to provide every tenant a dedicated share of the instance.

## Implementation
### Method 1
![](https://i.imgur.com/v8A7ghp.png)

The main idea of this method is that the network architecture is fixed, so the leaf switchs, i.e., the switchs directly connect to hosts, can decide whether to forward the broadcast packet to a specific host if the host is in same tenant with the source or to drop it.

#### Advantages:
1. Easy to implement.
2. The packet can easily be duplicated by openflow `FLOOD` in switchs which are not leaf.
#### Disadvantage
1. Need space to store additional information, e.g., leaf switches and their hosts.
2. The code is not flexible.
3. This code only works in specific situations. For example, there couldn't be two hosts within a same tenant under a single leaf switch.

#### Code
+ Define Leaf Switches
    ```python=
    """
    The controller need to keep a dictionary which contains all the
    leaf switches and hosts they connect to.
    """
    def _init_leaf(self):
        leaf = {}
        leaf[11] = [9, 10]
        leaf[12] = [11, 12]
        leaf[14] = [13, 14]
        leaf[15] = [15, 16]
        leaf[5] = [3, 4]
        leaf[4] = [1, 2]
        leaf[7] = [5, 6]
        leaf[8] = [7, 7]
        return leaf
    ```

    ```python=
    # if get a broadcast pack and the switch is a leaf
    if dst_int == broadcast_int and int(dpid) in self.leaf:
        src_tnt = self.tenant[src_int]
        for idx, out_host in enumerate(self.leaf[int(dpid)]):
            # check if the connected host is in the same tenant
            # with the source
            if self.tenant[out_host] == src_tnt and \
               out_host != src_int:
                out_port = idx+1
                dst = self._int_to_mac(out_host)
                break
        else:
            out_port = ofproto.OFPP_FLOOD

    elif dst in self.mac_to_port[dpid]:
        out_port = self.mac_to_port[dpid][dst]     

    else:
        out_port = ofproto.OFPP_FLOOD

    ```

### Method 2
![](https://i.imgur.com/wWEapbu.png)

The main idea of this method is that when a switch receive a broadcast packet, it will first find out all the destinations which are in the same tenant with the source host, and add their corresponding output ports to flow table.  

#### Advantage
1. The implementation is flexible, could work well on different network architecture.
2. Less copies of broadcast packet than method 1 because of not using openflow `FLOOD`.

#### Disadvantage
1. Need to be aware of duplicate broadcast packets.
2. Hard to implement.
```python=
# switch get a broadcast pack
if dst_int == broadcast_int:
    target_tnt = self.tenant[src_int]
    
    # find all destination in same tenant with source
    for try_dst in self.mac_to_port[dpid]:
        try:
            if self.tenant[self._mac_to_int(try_dst)] == \
                target_tnt and try_dst != src:
                the_out_port = self.mac_to_port[dpid][try_dst]
                if the_out_port != in_port and \
                   (the_out_port not in out_ports):
                    out_ports.append(the_out_port)
        except:
            pass
            
elif dst in self.mac_to_port[dpid]:
    out_ports.append(self.mac_to_port[dpid][dst])      

else:
    out_port = ofproto.OFPP_FLOOD
    out_ports.append(ofproto.OFPP_FLOOD)

# add all ports to actions
actions = [parser.OFPActionOutput(out_port) 
           for out_port in out_ports]

```

## Experiment
### Testing with server and client python script
![](https://i.imgur.com/keD2s7T.png)

### Testing with mininet pingall
![](https://i.imgur.com/lqqodRP.png)

## Bottleneck
In my proposal, I didn't notice that the broadcast packet's destination MAC address will be `ff:ff:ff:ff:ff:ff`, which is not the same as `pingall` command in mininet. After I followed my proposal to implement the code, only `pingall` command will success. Hence, I need to implement an additional method to handle broadcast packets.

While implementing the method 2, I encountered some bugs.
+ Broadcast packets will only be received by one host, but not all hosts in the same tenant. I realized that modifing the `acitons` and `match` in the `packet-in` function won't really duplicate the broadcast packets, which means that the packets will only be sent to one destination even I tried to use a for loop to send the packet to different destinations.
+ When I tried to test my program with the `server` and `client` python scripts, I found that the clients will receive many duplication of the broadcast packet. Then I realized that I need to add some additional rules to solve this problem. (In code line 11~12)

## Code
