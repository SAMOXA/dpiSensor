#include <linux/init.h> 
#include <linux/module.h>
#include <linux/netdevice.h> 

MODULE_LICENSE( "LGPL v3" ); 
MODULE_AUTHOR( "Samohin Anatoly <amdsamoxa@gmail.com>" ); 

static struct net_device *dev;

static int custom_dev_open( struct net_device *dev ) { 
   printk( KERN_INFO "Hit: dev_open(%s)\n", dev->name ); 
   netif_start_queue( dev );
   return 0; 
}

static int custom_dev_close( struct net_device *dev ) { 
   printk( KERN_INFO "Hit: dev_close(%s)\n", dev->name ); 
   netif_stop_queue( dev ); 
   return 0; 
} 

static int stub_start_xmit( struct sk_buff *skb, struct net_device *dev ) { 
   dev_kfree_skb( skb ); 
   return 0; 
}

static struct net_device_ops ndo = { 
   .ndo_open = custom_dev_open, 
   .ndo_stop = custom_dev_close, 
   .ndo_start_xmit = stub_start_xmit, 
}; 

static void custom_dev_setup( struct net_device *dev ) { 
   int j; 
   /* указать значение MAC-адреса */ 
   for( j = 0; j < ETH_ALEN; ++j ) 
      dev->dev_addr[ j ] = (char)j; 
   ether_setup( dev ); 
   dev->netdev_ops = &ndo;
   printk( KERN_INFO "dev_setup(%s)\n", dev->name );  
} 

static int __init interface_init( void ) { 
   printk( KERN_INFO "Loading stub network module:...." ); 
   dev = alloc_netdev( 0, "fict%d", custom_dev_setup ); 
   if( register_netdev( dev ) ) { 
      printk( KERN_INFO " Failed to register\n" ); 
      free_netdev( dev ); 
      return -1; 
   } 
   printk( KERN_INFO "Succeeded in loading %s!\n", dev_name( &dev->dev ) ); 
   return 0; 
} 

static void __exit interface_exit( void ) { 
   printk( KERN_INFO "Unloading stub network module\n" ); 
   unregister_netdev( dev ); 
   free_netdev( dev ); 
} 

module_init( interface_init ); 
module_exit( interface_exit );