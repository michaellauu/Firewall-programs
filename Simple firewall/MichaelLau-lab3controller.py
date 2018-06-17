# Michael Lau
# mlau10@ucsc.edu
# mlau10
# 1493231
# Lab 3
 
from pox.core import core
import pox.openflow.libopenflow_01 as of
 
log = core.getLogger()
 
class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
 
    # This binds our PacketIn event listener
    connection.addListeners(self)
 
  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 35
    msg.hard_timeout = 70
    ip = packet.find('ipv4')
    ARP = packet.find('arp')
    if ip is not None:
      TCP = packet.find('tcp')
      if TCP is not None:
        msg.data = packet_in
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)
      else:
        msg.data = packet_in
        self.connection.send(msg)
    else:
      if ARP is not None:
        msg.data = packet_in
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)
      else:
        msg.data = packet_in
        self.connection.send(msg)
 
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
 
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
 
    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)
 
def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
  