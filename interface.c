#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/moduleparam.h>
#include <net/arp.h>
#include <net/ip.h>
#include <linux/ip.h> 
#include <linux/tcp.h> 
#include <linux/udp.h> 
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/netpoll.h>
#include <linux/interrupt.h>

#define ERR(...) printk( KERN_ERR "! "__VA_ARGS__ )
#define LOG(...) printk( KERN_INFO "! "__VA_ARGS__ )
#define DBG(...) if( debug != 0 ) printk( KERN_INFO "! "__VA_ARGS__ )

#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN 20
#define TOTAL_UDP_HEADER_LEN IP_HDR_LEN+UDP_HDR_LEN
#define TOTAL_TCP_HEADER_LEN IP_HDR_LEN+TCP_HDR_LEN

//TODO set config from file or network
#define SOURCE_PORT 6666
#define DESTINATION_PORT 6666
#define DESTINATION_ADDRESS "192.168.1.129"
static unsigned char destination_mac[6] = {36, 253, 82, 189, 143, 250};

static u32 destination_address; 

MODULE_AUTHOR( "Samohin Anatoly" );
MODULE_LICENSE( "GPL v2" );
MODULE_VERSION( "0.3" );

static char* link = "eth0";
module_param( link, charp, 0 );

static char* output_dev = "eth1";
module_param( output_dev, charp, 0 );

static char* ifname = "virt"; 
module_param( ifname, charp, 0 );

static int debug = 1;
module_param( debug, int, 1 );

static struct net_device *child = NULL;
static struct net_device_stats stats;
static u32 child_ip;

struct priv {
   struct net_device *parent;
   struct net_device *output;
};

static char* strIP( u32 addr ) {     // диагностика IP в точечной нотации
   static char saddr[ MAX_ADDR_LEN ];
   sprintf( saddr, "%d.%d.%d.%d",
            ( addr ) & 0xFF, ( addr >> 8 ) & 0xFF,
            ( addr >> 16 ) & 0xFF, ( addr >> 24 ) & 0xFF
          );
   return saddr;
}

static u32 str_to_ip( char* str) {
   unsigned int temp[4];
   u32 addr = 0;
   sscanf( str, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]);
   addr += temp[0];
   addr += temp[1]<<8;
   addr += temp[2]<<16;
   addr += temp[3]<<24;
   return addr;
}

static char* strAR_IP( unsigned char addr[ 4 ] ) {
   static char saddr[ MAX_ADDR_LEN ];
   sprintf( saddr, "%d.%0d.%d.%d",
            addr[ 0 ], addr[ 1 ], addr[ 2 ], addr[ 3 ] );
   return saddr;
}

//<linux/if_arp.h> :
struct arp_eth_body {
   unsigned char  ar_sha[ ETH_ALEN ];     // sender hardware address      
   unsigned char  ar_sip[ 4 ];            // sender IP address            
   unsigned char  ar_tha[ ETH_ALEN ];     // target hardware address      
   unsigned char  ar_tip[ 4 ];            // target IP address            
};

static void send_packet_copy_to_collector( struct sk_buff *skb ) {
   struct sk_buff *skbc;
   struct udphdr *udph;
   struct iphdr *iph;
   struct ethhdr *eth;
   struct priv *priv;
   char *payload = skb->data;
   int err = 0;
   int length = skb->len;
   int total_len, ip_len, udp_len;
   unsigned long flags;
   static atomic_t ip_ident;
   struct netdev_queue *txq;
   const struct net_device_ops *ops;
   priv = netdev_priv( child );
   ops = priv->output->netdev_ops;
   udp_len = length + sizeof(*udph);
   ip_len = udp_len + sizeof(*iph);
   total_len = ip_len + LL_RESERVED_SPACE(priv->output);
   skbc = alloc_skb(total_len + child->needed_tailroom, GFP_ATOMIC);
   if(!skbc){
      return;
   }
   atomic_set(&skbc->users, 1);
   skb_reserve(skbc, total_len - length);
   skb_copy_to_linear_data(skbc, payload, length);
   skb_put(skbc, length);

   skb_push(skbc, sizeof( struct udphdr ) );
   skb_reset_transport_header(skbc);
   udph = udp_hdr(skbc);
   udph->source = htons(SOURCE_PORT);
   udph->dest = htons(DESTINATION_PORT);
   udph->len = htons(udp_len);
   udph->check = 0;
   udph->check = csum_tcpudp_magic(child_ip,
                                   destination_address,
                                   udp_len, IPPROTO_UDP,
                                   csum_partial(udph, udp_len, 0));
   if (udph->check == 0)
           udph->check = CSUM_MANGLED_0;
   skb_push(skbc, sizeof( struct iphdr ) );
   skb_reset_network_header(skbc);
   iph = ip_hdr(skbc);
   /* iph->version = 4; iph->ihl = 5; */
   put_unaligned(0x45, (unsigned char *)iph);
   iph->tos      = 0;
   iph->tot_len  = length + sizeof(*iph);
   put_unaligned(htons(ip_len), &(iph->tot_len));
   iph->id       = htons(atomic_inc_return(&ip_ident));
   iph->frag_off = 0;
   iph->ttl      = 64;//TODO set TTL
   iph->protocol = IPPROTO_UDP; /* IPPROTO_UDP in this case */
   iph->check    = 0;
   put_unaligned(child_ip, &(iph->saddr));
   put_unaligned(destination_address, &(iph->daddr));
   iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);
   eth = (struct ethhdr *) skb_push(skbc, ETH_HLEN);
   skb_reset_mac_header(skbc);
   skbc->protocol = eth->h_proto = htons(ETH_P_IP);
   memcpy(eth->h_source, priv->output->dev_addr, ETH_ALEN);
   memcpy(eth->h_dest, destination_mac, ETH_ALEN);
   skbc->dev = priv->output;
   print_hex_dump(KERN_DEBUG, "! send packet: ",
                                        DUMP_PREFIX_OFFSET, 16, 1,
                                        skbc->data,
                                        skbc->len, true);
   txq = netdev_get_tx_queue(priv->output, skb_get_queue_mapping(skbc));
   local_irq_save(flags);
   if (__netif_tx_trylock(txq)) {
      if (!netif_xmit_stopped(txq))
         err = ops->ndo_start_xmit(skbc, priv->output);
      if (err == NETDEV_TX_OK)
         txq_trans_update(txq);
      __netif_tx_unlock(txq);
   }
   local_irq_restore(flags);
}

static rx_handler_result_t handle_frame( struct sk_buff **pskb ) {
   struct sk_buff *skb = *pskb;
   if( skb->protocol == htons( ETH_P_IP ) ) {
      struct iphdr *ip = ip_hdr( skb );
      char *addr = strIP( ip->daddr );
      DBG( "rx: IP4 to IP=%s", addr );
      if( ip->daddr != child_ip ){
         send_packet_copy_to_collector( skb );
         return RX_HANDLER_PASS;
      }
   }
   else if( skb->protocol == htons( ETH_P_ARP ) ) {
      struct arphdr *arp = arp_hdr( skb );
      struct arp_eth_body *body = (void*)arp + sizeof( struct arphdr ); 
      int i, ip = child_ip;
      DBG( "rx: ARP for %s", strAR_IP( body->ar_tip ) );
      for( i = 0; i < sizeof( body->ar_tip ); i++ ) {
         if( ( ip & 0xFF ) != body->ar_tip[ i ] ) break;
         ip = ip >> 8;
      }
      if( i < sizeof( body->ar_tip ) ) {
         send_packet_copy_to_collector( skb );
         return RX_HANDLER_PASS; 
      }
   }
   else  {         // не ARP и не IP4
      send_packet_copy_to_collector( skb );
      return RX_HANDLER_PASS;
   }
   stats.rx_packets++;
   stats.rx_bytes += skb->len;
   DBG( "rx: injecting frame from %s to %s", skb->dev->name, child->name );
   skb->dev = child;
   return RX_HANDLER_ANOTHER;
}

static netdev_tx_t start_xmit( struct sk_buff *skb, struct net_device *dev ) {
   struct priv *priv = netdev_priv( dev );
   stats.tx_packets++;
   stats.tx_bytes += skb->len;
   if( priv->parent ) {
      skb->dev = priv->parent;
      skb->priority = 1;
      dev_queue_xmit( skb );
      LOG( "tx: injecting frame from %s to %s", dev->name, skb->dev->name );
      return 0;
   }
   return NETDEV_TX_OK;
}

static int open( struct net_device *dev ) {
   struct in_device *in_dev = dev->ip_ptr;
   struct in_ifaddr *ifa = in_dev->ifa_list;      /* IP ifaddr chain */
   char sdebg[ 40 ] = "";
   LOG( "%s: device opened", dev->name );
   child_ip = ifa->ifa_address;
   sprintf( sdebg, "%s:", strIP( ifa->ifa_address ) );
   strcat( sdebg, strIP( ifa->ifa_mask ) );
   netif_start_queue( dev );
   return 0;
}

static int stop( struct net_device *dev ) {
   LOG( "%s: device closed", dev->name );
   netif_stop_queue( dev );
   return 0;
}

static struct net_device_stats *get_stats( struct net_device *dev ) {
   return &stats;
}

static struct net_device_ops crypto_net_device_ops = {
   .ndo_open = open,
   .ndo_stop = stop,
   .ndo_get_stats = get_stats,
   .ndo_start_xmit = start_xmit,
};

static void setup( struct net_device *dev ) {
   int j;
   ether_setup( dev );
   memset( netdev_priv(dev), 0, sizeof( struct priv ) ); 
   dev->netdev_ops = &crypto_net_device_ops;
   for( j = 0; j < ETH_ALEN; ++j ) // fill in the MAC address with a phoney 
      dev->dev_addr[ j ] = (char)j;
}

int __init init( void ) {
   int err = 0;
   struct priv *priv;
   char ifstr[ 40 ];
   destination_address = str_to_ip( DESTINATION_ADDRESS );
   sprintf( ifstr, "%s%s", ifname, "%d" );
   child = alloc_netdev( sizeof( struct priv ), ifstr, setup );
   if( child == NULL ) {
      ERR( "%s: allocate error", THIS_MODULE->name ); return -ENOMEM;
   }
   priv = netdev_priv( child );
   priv->parent = __dev_get_by_name( &init_net, link ); // parent interface  
   if( !priv->parent ) {
      ERR( "%s: no such net: %s", THIS_MODULE->name, link );
      err = -ENODEV; goto err;
   }
   if( priv->parent->type != ARPHRD_ETHER && priv->parent->type != ARPHRD_LOOPBACK ) {
      ERR( "%s: illegal net type", THIS_MODULE->name );
      err = -EINVAL; goto err;
   }
   priv->output = __dev_get_by_name( &init_net, output_dev ); // output interface  
   if( !priv->output ) {
      ERR( "%s: no such output net: %s", THIS_MODULE->name, output_dev );
      err = -ENODEV; goto err;
   }
   if( priv->parent->type != ARPHRD_ETHER && priv->parent->type != ARPHRD_LOOPBACK ) {
      ERR( "%s: illegal output net type", THIS_MODULE->name );
      err = -EINVAL; goto err;
   }
   /* also, and clone its IP, MAC and other information */
   memcpy( child->dev_addr, priv->parent->dev_addr, ETH_ALEN );
   memcpy( child->broadcast, priv->parent->broadcast, ETH_ALEN );
   if( ( err = dev_alloc_name( child, child->name ) ) ) {
      ERR( "%s: allocate name, error %i", THIS_MODULE->name, err );
      err = -EIO; goto err;
   }
   register_netdev( child );
   rtnl_lock();
   dev_set_promiscuity(priv->parent, 1);
   if(netdev_rx_handler_register( priv->parent, &handle_frame, NULL ) < 0){
      ERR( "%s: rx_handler_register, error %i", THIS_MODULE->name, err );
      rtnl_unlock();
      err = -EBUSY; goto err;
   }
   rtnl_unlock();
   LOG( "module %s loaded", THIS_MODULE->name );
   LOG( "%s: create link %s", THIS_MODULE->name, child->name );
   LOG( "%s: registered rx handler for %s", THIS_MODULE->name, priv->parent->name );
   return 0;
err:
   free_netdev( child );
   return err;
}

void __exit exit( void ) {
   struct priv *priv = netdev_priv( child );
   rtnl_lock();
   netdev_rx_handler_unregister( priv->parent );
   rtnl_unlock();
   LOG( "%s: unregister rx handler for %s\n", THIS_MODULE->name, priv->parent->name );
   unregister_netdev( child );
   free_netdev( child );
   LOG( "module %s unloaded", THIS_MODULE->name );
}

module_init( init );
module_exit( exit );