package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	class RipEntry {
		int mask;
		int addr;
		int metric;
		int nextHop;
		long lastUpdated;

		// All-args constructor to initialize every field
		RipEntry(int addr, int mask, int metric, int nextHop, long lastUpdated) {
			this.addr = addr;
			this.mask = mask;
			this.metric = metric;
			this.nextHop = nextHop;
			this.lastUpdated = lastUpdated;
		}

	}

	private Map<Integer, RipEntry> ripMap = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets */

		switch (etherPacket.getEtherType()) {
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
				break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return;
		}

		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP
				&& ((UDP) ipPacket.getPayload()).getDestinationPort() == UDP.RIP_PORT) {
			// handle RIP
			UDP udp = (UDP) ipPacket.getPayload();
			RIPv2 rip = (RIPv2) udp.getPayload();
			if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
				Ethernet responseEthernet = new Ethernet();
				IPv4 responseIp = new IPv4();
				UDP responseUdp = new UDP();
				RIPv2 responseRip = new RIPv2();

				responseUdp.setSourcePort(UDP.RIP_PORT);
				responseUdp.setDestinationPort(UDP.RIP_PORT);
				responseIp.setTtl((byte) 1);
				responseIp.setSourceAddress(inIface.getIpAddress());
				responseIp.setDestinationAddress(ipPacket.getSourceAddress());
				responseIp.setProtocol(IPv4.PROTOCOL_UDP);
				responseEthernet.setSourceMACAddress(inIface.getMacAddress().toBytes());
				responseEthernet.setDestinationMACAddress(etherPacket.getSourceMACAddress());
				responseEthernet.setEtherType(Ethernet.TYPE_IPv4);
				responseRip.setCommand(RIPv2.COMMAND_RESPONSE);
				responseUdp.setPayload(responseRip);
				for (RipEntry entry : ripMap.values()) {
					responseRip.addEntry(new RIPv2Entry(entry.addr, entry.mask, entry.metric));
				}
				responseIp.setPayload(responseUdp);
				responseEthernet.setPayload(responseIp);
				responseEthernet.serialize();
				this.sendPacket(responseEthernet, inIface);
			} else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
				List<RIPv2Entry> entries = rip.getEntries();
				for (RIPv2Entry entry : entries) {
					int metric = entry.getMetric() + 1;
					if (ripMap.containsKey(entry.getAddress() & entry.getSubnetMask())) {
						ripMap.get(entry.getAddress() & entry.getSubnetMask()).lastUpdated = System.currentTimeMillis();
						if (metric < ripMap.get(entry.getAddress() & entry.getSubnetMask()).metric) {
							ripMap.get(entry.getAddress() & entry.getSubnetMask()).metric = metric;
							this.routeTable.update(entry.getAddress() & entry.getSubnetMask(), entry.getSubnetMask(),
									ipPacket.getSourceAddress(), inIface);
						}
						if (metric >= 16) {
							RouteEntry cur = this.routeTable.lookup(entry.getAddress());
							if (inIface.equals(cur.getInterface())) {
								ripMap.get(entry.getAddress() & entry.getSubnetMask()).metric = 16;
								this.routeTable.remove(entry.getAddress() & entry.getSubnetMask(),
										entry.getSubnetMask());
							}
						}
					} else {
						if (metric < 16) {
							ripMap.put(entry.getAddress() & entry.getSubnetMask(),
									new RipEntry(entry.getAddress(), entry.getSubnetMask(), metric,
											ipPacket.getSourceAddress(), System.currentTimeMillis()));
							this.routeTable.insert(entry.getAddress() & entry.getSubnetMask(), entry.getSubnetMask(),
									ipPacket.getSourceAddress(), inIface);
						}
					}
				}
			}
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			return;
		}
		
		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	public void startRIP() {
		for (Iface iface : this.interfaces.values()) {
			this.routeTable.insert(iface.getIpAddress() & iface.getSubnetMask(), 0, iface.getSubnetMask(), iface);
			ripMap.put(iface.getIpAddress() & iface.getSubnetMask(),
					new RipEntry(iface.getIpAddress() & iface.getSubnetMask(), iface.getSubnetMask(), 1, 0,
							-1));
		}
		for (Iface iface : this.interfaces.values()) {
			Ethernet ethernet = new Ethernet();
			IPv4 ip = new IPv4();
			UDP udp = new UDP();
			RIPv2 rip = new RIPv2();
			udp.setSourcePort(UDP.RIP_PORT);
			udp.setDestinationPort(UDP.RIP_PORT);
			ip.setTtl((byte) 1);
			ip.setSourceAddress(iface.getIpAddress());
			ip.setDestinationAddress("224.0.0.9");
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ethernet.setSourceMACAddress(iface.getMacAddress().toBytes());
			ethernet.setDestinationMACAddress(("FF:FF:FF:FF:FF:FF"));
			ethernet.setEtherType(Ethernet.TYPE_IPv4);
			rip.setCommand(RIPv2.COMMAND_REQUEST);
			for (RipEntry entry : ripMap.values()) {
					rip.addEntry(new RIPv2Entry(entry.addr, entry.mask, entry.metric));
			}
			udp.setPayload(rip);
			ip.setPayload(udp);
			ethernet.setPayload(ip);
			ethernet.serialize();
			this.sendPacket(ethernet, iface);
		}

		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
		Runnable timeOut = () -> {
			ArrayList<Integer> toRemove = new ArrayList<>();

			for (RipEntry entry : ripMap.values()) {
				if (entry.lastUpdated != -1 && System.currentTimeMillis() - entry.lastUpdated >= 30000) {
					toRemove.add(entry.addr & entry.mask);
				}
			}

			for (Integer key : toRemove) {
				RipEntry removed = ripMap.remove(key);
				this.routeTable.remove(removed.addr & removed.mask, removed.mask);
			}
		};

		Runnable unsol = () -> {
			for (Iface iface : interfaces.values()) {
				Ethernet ethernet = new Ethernet();
				IPv4 ip = new IPv4();
				UDP udp = new UDP();
				RIPv2 rip = new RIPv2();
				udp.setSourcePort(UDP.RIP_PORT);
				udp.setDestinationPort(UDP.RIP_PORT);
				ip.setTtl((byte) 1);
				ip.setSourceAddress(iface.getIpAddress());
				ip.setDestinationAddress("224.0.0.9");
				ip.setProtocol(IPv4.PROTOCOL_UDP);
				ethernet.setSourceMACAddress(iface.getMacAddress().toBytes());
				ethernet.setDestinationMACAddress(("FF:FF:FF:FF:FF:FF"));
				ethernet.setEtherType(Ethernet.TYPE_IPv4);
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				for (RipEntry entry : ripMap.values()) {
					rip.addEntry(new RIPv2Entry(entry.addr, entry.mask, entry.metric));
				}
				udp.setPayload(rip);
				ip.setPayload(udp);
				ethernet.setPayload(ip);
				ethernet.serialize();
				this.sendPacket(ethernet, iface);
			}
		};

		// Periodic debug dump of RIP entries (every 30 seconds)
		Runnable debugDump = () -> {
			try {
				long now = System.currentTimeMillis();
				System.out.println("[RIP][debug] total entries=" + ripMap.size());
				// Snapshot to avoid concurrent modification while iterating
				java.util.List<RipEntry> snapshot = new java.util.ArrayList<>(ripMap.values());
				for (RipEntry re : snapshot) {
					String addrStr = IPv4.fromIPv4Address(re.addr);
					String maskStr = IPv4.fromIPv4Address(re.mask);
					String nhStr = IPv4.fromIPv4Address(re.nextHop);
					long ageSec = (re.lastUpdated < 0) ? -1 : ((now - re.lastUpdated) / 1000L);
					System.out.println(String.format(
						"[RIP][entry] %s mask %s metric %d nextHop %s age=%ds",
						addrStr, maskStr, re.metric, nhStr, ageSec));
				}
			} catch (Exception e) {
				System.err.println("[RIP][debug] dump error: " + e.getMessage());
			}
		};

		scheduler.scheduleAtFixedRate(unsol, 0, 10, TimeUnit.SECONDS);
		scheduler.scheduleAtFixedRate(timeOut, 0, 1, TimeUnit.SECONDS);
		scheduler.scheduleAtFixedRate(debugDump, 0, 10, TimeUnit.SECONDS);

	}
}
