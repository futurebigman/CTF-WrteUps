#include "out.h"



int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void FUN_00101020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00101083)
// WARNING: Removing unreachable block (ram,0x0010108f)

void deregister_tm_clones(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x001010c4)
// WARNING: Removing unreachable block (ram,0x001010d0)

void register_tm_clones(void)

{
  return;
}



void __do_global_dtors_aux(void)

{
  if (completed_0 != '\0') {
    return;
  }
  __cxa_finalize(__dso_handle);
  deregister_tm_clones();
  completed_0 = 1;
  return;
}



void frame_dummy(void)

{
  register_tm_clones();
  return;
}



void sigma_encrypt(char *message,uint8_t *out,size_t len)

{
  uint32_t uVar1;
  long lVar2;
  long in_FS_OFFSET;
  size_t len_local;
  uint8_t *out_local;
  char *message_local;
  uint8_t k;
  int i;
  uint32_t w;
  size_t i_1;
  uint8_t key_bytes [16];
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  for (i = 0; i < 4; i = i + 1) {
    uVar1 = sigma_words[i];
    key_bytes[i << 2] = (uint8_t)uVar1;
    key_bytes[i * 4 + 1] = (uint8_t)(uVar1 >> 8);
    key_bytes[i * 4 + 2] = (uint8_t)(uVar1 >> 0x10);
    key_bytes[i * 4 + 3] = (uint8_t)(uVar1 >> 0x18);
  }
  for (i_1 = 0; i_1 < len; i_1 = i_1 + 1) {
    out[i_1] = message[i_1] ^ key_bytes[(uint)i_1 & 0xf] + (char)i_1;
  }
  if (lVar2 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00101312)
// WARNING: Unknown calling convention

int main(void)

{
  long lVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  long in_FS_OFFSET;
  int ok;
  size_t len;
  char *message;
  uint8_t user_tag [18];
  char buf [256];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter flag: ");
  pcVar3 = fgets(buf,0x100,stdin);
  if (pcVar3 == (char *)0x0) {
    iVar2 = 1;
  }
  else {
    sVar4 = strcspn(buf,"\n");
    buf[sVar4] = '\0';
    sVar4 = strlen(buf);
    if (sVar4 == 0x1a) {
      iVar2 = strncmp(buf,"SECCON{",7);
      if ((iVar2 == 0) && (buf[0x19] == '}')) {
        sigma_encrypt(buf + 7,user_tag,0x12);
        iVar2 = memcmp(user_tag,flag_enc,0x12);
        if (iVar2 == 0) {
          puts("correct flag!");
          iVar2 = 0;
        }
        else {
          puts("wrong :(");
          iVar2 = 1;
        }
      }
      else {
        puts("wrong :(");
        iVar2 = 1;
      }
    }
    else {
      puts("wrong :(");
      iVar2 = 1;
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void _fini(void)

{
  return;
}