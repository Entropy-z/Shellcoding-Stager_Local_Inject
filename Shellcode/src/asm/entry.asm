section .text                  
global WinMain

EXTERN Main
WinMain:                         
    push rsi                      
    mov  rsi, rsp                 
    and  rsp, 0xFFFFFFFFFFFFFFF0  
    sub  rsp, 0x20                
    call Main                     
    mov  rsp, rsi                 
    pop  rsi                      
    ret                           