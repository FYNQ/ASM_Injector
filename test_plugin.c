#include <stdio.h>

static int res;
int resi;
int res2;

char bufx[] = "this is a test";
/*!
 * \brief Function which is called upon function exit. The function call is inserted by the compiler.
 * \param this_fn Address of the caller function.
 * \param call_site Return address to the function which called this_fn
 */
/*
__attribute__((no_instrument_function))
void __cyfg_profile_func_enter(void *this_fn, void *call_site) {
    char* str = "cyg enter\n";
    long len = strlen(str);
    int ret = 0;
    printf("this_fn: %p call_site: %p\n", this_fn, call_site);

    __asm__("movq $1, %%rax \n\t"
            "movq $1, %%rdi \n\t"
            "movq %1, %%rsi \n\t"
            "movl %2, %%edx \n\t"
            "syscall"
            : "=g"(ret)
            : "g"(str), "g" (len));
}

*/

struct fs_callbacks {
    int (*open_file)();
    int (*close_file)();
    int (*read_bytes)();
    int (*write_bytes)();
    struct fs_callbacks *next;
} FileSystems [10];


int write_ext2 () {
    printf("\nCALLED EXT2\n");
    //void * addr1 = __builtin_return_address(1);
    //printf("\n|addr1 %lp|\n", addr1);
    //void * addr0 = __builtin_return_address(0);
    //printf("\n|addr0 %lp|\n", addr0);
}



struct info{
    int a;
    int b;
    char *c;
};

struct info g_info;

enum STATE{working, idle};


inline int 
add1(char a, unsigned int b){
    printf("\nadd1\n");
    return a + b;
}

int state(enum STATE a, char *k) {
    printf("\ncalled state\n");
}

int add2(float a, int b){
    printf("\ncalled add2\n");
    int c = a + b;
    return c;
}

int fun_void(void *a){
    printf("\ncalled fun_void\n");
    return a;
}


int blub2 (int a){
    //void * addr1 = __builtin_return_address(0);
    //void * addr2 = __builtin_return_address(1);
    //printf("\n|addr1 %lp|\n", addr1);
    //printf("\n|addr2 %lp|\n", addr2);
    //printf("\ncalled blub2: %d\n", a);
    return 0;
}


int blub(struct info *ptr_to_struct, int b){
    printf("\nblub\n");
    int c = ptr_to_struct->a + b;
    return c;
}





#include<pthread.h>
pthread_t tid[2];

void* doSomeThing(void *arg)
{
    char fun[] = "test me";
    printf("\n%s\n", fun);
    unsigned long i = 0;
    pthread_t id = pthread_self();

    if(pthread_equal(id,tid[0]))
    {
        printf("\n First thread processing\n");
    }
    else
    {
        printf("\n Second thread processing\n");
    }

    for(i=0; i<(0xFFFFFFFF);i++);

    return NULL;
}

int main(int argc, char **argv) {
    char fun[] = "main";
    printf("\n%s\n", fun);
    struct info l_info;
    enum STATE s;
    s =  idle;
    blub2(4);
    //state(s, "ggg");
    struct fs_callbacks *f = &FileSystems [0];
    f->write_bytes = write_ext2;
    f->write_bytes();

    struct minfo{
        int a;
        int b;
        char *c;
    };
    static int blub_static = 5;
    struct minfo ldef;
    l_info.a = 5;
    //int c = blub(&ldef,4);
    ldef = (struct minfo) { .a = 1, .b = 0 }; 
    int x;
    int *z;
    int i = 20;
    x = 20;
    l_info.a = 20;
    l_info.b = 20;
    ldef.b = 20;
    //x = add2(20,
    //       30);
    //printf("\n%d\n", x);

   // for (i = 0; i < 20; i++){
   //     printf("a + b = %d\n", res);
   // }
    int err;
    i = 0;
    /*
    while(i < 2)
    {
        err = pthread_create(&(tid[i]), NULL, &doSomeThing, NULL);
        if (err != 0)
            printf("\ncan't create thread :[%s]", strerror(err));
        else
            printf("\n Thread created successfully\n");

        i++;
    }
    */
    //sleep(5);
    return 0;
}

