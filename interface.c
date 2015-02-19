#include <linux/init.h> 
#include <linux/module.h> 

MODULE_LICENSE( "LGPL v3" ); 
MODULE_AUTHOR( "Samohin Anatoly <amdsamoxa@gmail.com>" ); 

static int __init interface_init( void ) { 
   printk( "Interface module init!\n" ); 
   return 0; 
} 
static void __exit interface_exit( void ) { 
   printk( "Interface module exit!\n" ); 
} 
module_init( interface_init ); 
module_exit( interface_exit );