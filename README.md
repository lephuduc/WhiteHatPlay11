# WhiteHatPlay11

## re01-WhiteHatPlay11v1 - 128pts

![image](https://user-images.githubusercontent.com/88520787/176362334-f62ca54b-7199-4390-bdeb-75aa199397a9.png)

Check file bằng DiE và mở bằng IDA32:


![image](https://user-images.githubusercontent.com/88520787/176362651-4d7a4132-625c-4791-a4b9-88158a776cb6.png)

![image](https://user-images.githubusercontent.com/88520787/176362692-c2a3fb01-4ab1-437b-9922-53e77fcfb1a8.png)

Input của mình sau khi nhập vào Buffer thì sẽ được đưa vào hàm `sub_4010A0()` xử lí:

![image](https://user-images.githubusercontent.com/88520787/176364687-3f06681f-2516-455b-b5b6-521989231b96.png)

Trong hàm này, mình đã đổi 0x55 thành 85 cho dễ nhìn, tới đây mình thấy nghi nghi, thử bấm vào `byte_40EFB0` xem nó là gì:

![image](https://user-images.githubusercontent.com/88520787/176364926-60f8f87b-dacd-4b27-9618-9696508c4dcb.png)

Rồi luôn, tới đây thì mình khá chắc là chương trình này dùng `base85`, mình thử kiếm `cipher` trong string và xref, mình thấy 2 đoạn này khá phù hợp:

![image](https://user-images.githubusercontent.com/88520787/176365158-adfc5d6c-e8bb-4822-a7d9-8ede8bd1b5b3.png)

Thử trên cyber chef và bùm:

![image](https://user-images.githubusercontent.com/88520787/176365683-f833a682-0b13-4e6a-8f7c-ea689e946f3e.png)

Flag: WhiteHat{Whit3H4t11H4v34N1C3D4yR3VeRs31!.Whit3H4t11THISIS4TR4p4YOU?}

## re02-

Lần này đề cho mình file dll, tiếp tục check và mở bằng IDA32 lên xem:

![image](https://user-images.githubusercontent.com/88520787/176366203-b72bd7b1-8378-4564-b947-399a4e7fb6c4.png)
 
Trong IDA mình thấy 1 hàm tên là WhiteHat khá là khả nghi:

```c
char WhiteHat()
{
  int v0; // edi
  int v1; // esi
  int v2; // kr04_4
  char *v3; // eax
  char *v4; // ecx
  void *v5; // eax
  void **v6; // eax
  int v7; // eax
  int i; // ecx
  int v10; // [esp+0h] [ebp-4B4h]
  int v11; // [esp+10h] [ebp-4A4h]
  int v12[14]; // [esp+14h] [ebp-4A0h]
  void *v13[4]; // [esp+4Ch] [ebp-468h] BYREF
  int v14; // [esp+5Ch] [ebp-458h]
  unsigned int v15; // [esp+60h] [ebp-454h]
  void *v16; // [esp+64h] [ebp-450h]
  int v17; // [esp+74h] [ebp-440h]
  unsigned int v18; // [esp+78h] [ebp-43Ch]
  char Str[264]; // [esp+7Ch] [ebp-438h] BYREF
  char v20; // [esp+184h] [ebp-330h] BYREF
  char v21[263]; // [esp+185h] [ebp-32Fh] BYREF
  char Destination[264]; // [esp+28Ch] [ebp-228h] BYREF
  char v23[268]; // [esp+394h] [ebp-120h] BYREF
  int v24; // [esp+4B0h] [ebp-4h]

  v11 = 1887667281;
  v12[0] = 1882219565;
  v12[1] = 743254827;
  v12[2] = 762456936;
  v12[3] = -2105317328;
  v12[4] = 1865175935;
  v12[5] = -2004341935;
  v12[6] = 2139565390;
  v12[7] = 1848467079;
  v20 = 0;
  memset(v21, 0, 0x103u);
  memset(Str, 0, 260);
  memset(Destination, 0, 260);
  memset(v23, 0, 260);
  v0 = 0;
  v18 = 15;
  v17 = 0;
  LOBYTE(v16) = 0;
  v24 = 1;
  v15 = 15;
  v14 = 0;
  LOBYTE(v13[0]) = 0;
  sub_10003997("___________________________________________________________________________\n");
  sub_10003997("                                                         __                \n");
  sub_10003997(" _ _ _ _   _ _       _____     _      _____ _           |  |   ___   ___   \n");
  sub_10003997("| | | | |_|_| |_ ___|  |  |___| |_   |  _  | |___ _ _   |  |  |_  | |_  |  \n");
  sub_10003997("| | | |   | |  _| -_|     | .'|  _|  |   __| | .'| | |  |__|   _| |_ _| |_ \n");
  sub_10003997("|_____|_|_|_|_| |___|__|__|__,|_|    |__|  |_|__,|_  |  |__|  |_____|_____|\n");
  sub_10003997("                                                 |___|                     \n");
  sub_10003997("___________________________________________________________________________\n");
  sub_10003997("\n********Let's Play!********\n");
  sub_10003997("Try to guess the flag: ");
  gets_s(Str, 0x104u);
  v1 = strlen(Str);
  if ( v1 < 40 )
  {
    while ( 1 )
    {
      sub_10003997("\nHmm, enter something more interesting: ");
      gets_s(Str, 0x104u);
      v2 = strlen(Str);
      v1 = v2;
      if ( v2 > 41 )
        break;
      if ( v2 >= 40 )
        goto LABEL_6;
    }
    sub_10003997("Great! It may be the right flag :)\n");
  }
LABEL_6:
  sub_10003997("Checking...\n");
  Sleep(0x3E8u);
  strncpy_s(Destination, 0x104u, Str, 0x24u);
  if ( !strstr(Str, "@") )
    goto LABEL_41;
  v3 = strrchr(Str, 64);
  strncpy_s(v23, 0x104u, v3, 5u);
  v4 = Str;
  if ( dword_10018FD4 != 1 )
    v4 = Destination;
  sub_10001EC0(v4, &v20);
  sub_100017A0("QDIwMjI=", 8u);
  v5 = (void *)sub_10001430(v10);
  sub_100023E0(v13, v5);
  if ( v12[13] >= 0x10u )
    j__free((void *)v12[8]);
  v6 = v13;
  if ( v15 >= 0x10 )
    v6 = (void **)v13[0];
  v7 = strcmp(v23, (const char *)v6);
  if ( v7 )
    v7 = v7 < 0 ? -1 : 1;
  if ( v7 )
  {
LABEL_41:
    sub_10003997("Oh no! That is a wrong flag! Try again!!1\n");
  }
  else
  {
    sub_10003997("Great! Keep moving...\n");
    Sleep(0x3E8u);
    if ( FindWindowA("OllyDbg", 0) )
      ExitProcess(0);
    if ( FindWindowA("x32dbg", 0) || sub_10001DA0(L"OllyDbg.exe") || sub_10001DA0(L"x32dbg.exe") )
      ExitProcess(0);
    if ( dword_10018FD4 == 1 || v1 != 41 )
    {
      sub_10003997("\nOops! Did you forget anything?\n");
      sub_10003997("That is a wrong flag! Try again!!1\n");
    }
    else
    {
      for ( i = 0; i < 36; i += 6 )
      {
        if ( v21[i - 1] == *((_BYTE *)&v12[-1] + i) )
          ++v0;
        if ( v21[i] == *((_BYTE *)&v11 + i + 1) )
          ++v0;
        if ( v21[i + 1] == *((_BYTE *)&v11 + i + 2) )
          ++v0;
        if ( v21[i + 2] == *((_BYTE *)&v11 + i + 3) )
          ++v0;
        if ( v21[i + 3] == *((_BYTE *)v12 + i) )
          ++v0;
        if ( v21[i + 4] == *((_BYTE *)v12 + i + 1) )
          ++v0;
      }
      if ( v0 == 36 )
      {
        sub_10003997("\nGreat Flag!\n");
        sub_10003997("Congratulations!\n");
      }
    }
  }
  sub_10003997("\n");
  system("pause");
  if ( v15 >= 0x10 )
    j__free(v13[0]);
  v15 = 15;
  v14 = 0;
  LOBYTE(v13[0]) = 0;
  if ( v18 >= 0x10 )
    j__free(v16);
  return 1;
}
```
Đoạn này sẽ check len của input

```c
LABEL_6:
  print("Checking...\n");
  Sleep(0x3E8u);
  strncpy_s(Destination, 0x104u, Str, 0x24u);
  if ( !strstr(Str, "@") )
    goto FAIl;
  v3 = strrchr(Str, 64);
  strncpy_s(v22, 0x104u, v3, 5u);
  v4 = Str;
  if ( dword_10018FD4 != 1 )
    v4 = Destination;
  sub_10001EC0(v4, &v19);
  sub_100017A0(v16, "QDIwMjI=", 8u);
  v5 = sub_10001430(v10);
  sub_100023E0(v13, v5);
  if ( v12[13] >= 0x10u )
    j__free(v12[8]);
  v6 = v13;
  if ( v15 >= 0x10 )
    v6 = v13[0];
  v7 = strcmp(v22, v6);
  if ( v7 )
    v7 = v7 < 0 ? -1 : 1;
  if ( v7 )
  {
FAIl:
    print("Oh no! That is a wrong flag! Try again!!1\n");
```
Đoạn check này chương trình sẽ lấy 36 kí tự đầu và lưu vào v4, còn 5 kí tự cuối, 5 kí tự cuối sẽ được `cmp` với b64decode của `QDIwMjI=`:

![image](https://user-images.githubusercontent.com/88520787/176368660-d98ec1ad-ed2f-4808-8911-2bf4afc1b816.png)

36 kí tự đầu sẽ được xử lí qua hàm `sub_10001EC0`:
```c
int __fastcall sub_10001EC0(const char *a1, _BYTE *a2)
{
  unsigned int v4; // eax
  _BYTE *v5; // edx
  int v6; // esi
  unsigned int v7; // ebx

  v4 = strlen(a1);
  if ( v4 )
  {
    v5 = a2;
    v6 = a1 - a2;
    v7 = v4;
    do
    {
      *v5 = (v5[v6] ^ 0x11) + 11;
      ++v5;
      --v4;
    }
    while ( v4 );
    a2[v7] = 0;
    return 1;
  }
  else
  {
    *a2 = 0;
    return 1;
  }
}
```
Cụ thể thì hàm này chỉ là `xor` từng kí tự input với lại 0x11

Tại dòng 119, ta sẽ thấy đoạn check 36 kí tự đầu:

```c
for ( i = 0; i < 36; i += 6 )
      {
        if ( v20[i - 1] == *(&v12[-1] + i) )
          ++v0;
        if ( v20[i] == *(&v11 + i + 1) )
          ++v0;
        if ( v20[i + 1] == *(&v11 + i + 2) )
          ++v0;
        if ( v20[i + 2] == *(&v11 + i + 3) )
          ++v0;
        if ( v20[i + 3] == *(v12 + i) )
          ++v0;
        if ( v20[i + 4] == *(v12 + i + 1) )
          ++v0;
      }
```
Sau khi mình xem trên stack thì mình `v11` nằm ngay trước `v12` nên là khi viết script mình sẽ gộp 2 bytes này chung:

![image](https://user-images.githubusercontent.com/88520787/176369395-a6cc72a5-a033-4b0e-88af-5da7aa0cf2de.png)

```py
x= [0x70,0x83,0x84,0x51,0x70,0x30,0x64,0x2D,0x2C,0x4D,0x2B,0x2B,0x2D,0x72,0x2B,0x68,0x82,0x83,0x68,0x30,0x6F,0x2C,0x53,0x7F,0x88,0x88,0x2B,0x51,0x7F,0x87,0x2D,0x4E,0x6E,0x2D,0x5E,0x87]
for i in range(0,len(x),4):
    t = x[i:i+4][::-1]
    for c in t:
        print(chr((c-11)^0x11),end = "") #Whit3H4t11S0L1v34LifeY0uW1llR3memB3r
```
Flag: `WhiteHat{Whit3H4t11S0L1v34LifeY0uW1llR3memB3r@2022}


