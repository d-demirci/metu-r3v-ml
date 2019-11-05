from bin2op import parse, unique, counts, nextIndex
import numpy as np
import math
#https://towardsdatascience.com/different-techniques-to-represent-words-as-vectors-word-embeddings-3e4b9ab7ceb4

""" as mentioned in the above article, every instruction is a sentence in this study. 
i am going to use whole instruction without addresses. (dropping out the addresses in instructions (0x840000 etc.) 
e.g 
while ['push', 'ebx'] -> "push ebx" will be a sentence
['push', '0x402058'] -> "push 0x402058" won't be used as a sentence instead "push addr" will be used. 

all addresses with a pattern of r'(0x[0-9a-fA-F]+)(?:)?' will be replaced with addr. 
DWORD PTR, QWORD PTR and BYTE PTR will be replaced with APTR

"""
file = './a.exe'
syntax = "intel"
shellcode, code, opcodes, operands, instructions = parse(file, syntax, None)
"""
Sample Data
--------------------instructions--------------------

[
'push ebp','push ebx','push edi','push esi','sub esp addr','mov eax APTR [esp+addr]','mov ecx APTR ds:addr','mov esi APTR [esp+addr]','mov ebx APTR [esp+addr]','cmp eax addr','mov APTR [esp+addr] ecx','je addr','mov edi APTR [esp+addr]','cmp eax addr','je addr','test eax eax','jne addr','mov esi esp','push addr','push esi','push edi','call addr','add esp addr','push edi','call addr','add esp addr','test eax eax','je addr','push APTR [esp+addr]','push esi','push addr','jmp addr','mov ebp APTR [esp+addr]','push esi','push addr','call addr','add esp addr','mov esi eax','push esi','call addr','add esp addr','mov edi eax','cmp edi addr','jg addr','push addr','push addr','push addr','call addr','add esp addr','push addr','push ebp','call addr','add esp addr','xor ecx ecx','cmp APTR [esp+addr] addr','setne cl','cmp eax addr','cmovne ecx eax','test ecx ecx','jne addr','push edi','push esi','push addr','push ebx','call addr','add esp addr','mov APTR [esi+edi*1-addr] addr','jmp addr','mov ebp esp','push addr','push ebp','push edi','call addr','add esp addr','push esi','push ebp','push addr','call addr','add esp addr','jmp addr','push esi','push addr','call addr','add esp addr','mov esi eax','test esi esi','je addr','push esi','push ebx','call addr','add esp addr','push esi','call addr','add esp addr','mov ecx APTR [esp+addr]','call addr','add esp addr','pop esi','pop edi','pop ebx','pop ebp','ret','push ebp','push ebx','push edi','push esi','push eax','mov edi APTR [esp+addr]','xor ebp ebp','test edi edi','jle addr','mov ecx APTR [esp+addr]','mov eax edi','sub eax ebp','lea esi [ecx+ebp*1]','push eax','push addr','push esi','call addr','add esp addr',
....................

"""

"""
Step 1: Identify unique words in the complete text data. In our case, the list is as follows we use unique opcodes and unique operands:
--------------------unique_opcodes--------------------

'push','sub','mov','cmp','je','test','jne','call','add','jmp','jg','xor','setne','cmovne','pop','ret','jle','lea','inc','jl','int3','dec','js','or','movsx','jae','ja','sbb','shl','jge','setg','movzx','bswap','cmovle','shr','not','and','sete','jns','neg','cvtsi2sd','divsd','movsd','fstp','mulsd','cvttsd2si','sar','cmovg','cmovl','jb','cmove','movaps','movups','seta','cmovb','imul','cmovs','jbe','rep','bt','div','cmovbe','mul','cmovge','cmovns','setb','cmova','adc','cdq','idiv','movd','pshufd','movdqu','punpckldq','punpcklqdq','cmovae','pxor','pinsrw','punpcklbw','punpcklwd','pslld','por','setle','shld','setae','setbe','movq','rol','paddd','movdqa','psrld','shufps','andps','pshuflw','psrlq','pand','pshufhw','packuswb','pandn','xorps','seto','lahf','sahf','ror','psrad','psrlw','punpckhbw','punpckhwd','punpckhdq','shrd','setns','setl','cwde','setge','pcmpeqd','cvtss2sd','addsd','sets','packssdw','paddw','pcmpeqb','pmovmskb','bnd','xchg','int','data16','pushf','fnclex','lock','movs','cpuid','xgetbv','fwait','cs','nop','popf','vfrczpd','palignr','std','cld','in','stos','movlhps','bsf','bsr','leave','pcmpistri','repnz','pinsrb','psrldq','jno','arpl','les','cmps','scas','lds','jecxz','(bad)','cbw','hlt','cmc','fldz','clc','icebp','bts','fld','vxorps','vpcmpeqb','vpmovmskb','vzeroupper','vpcmpeqw','pcmpeqw','rcr','fnstsw','stmxcsr','ldmxcsr','fstcw','fldcw','stc','fst','fnstcw','fnstenv','fldenv','fistp','fstsw','fld1','fdivp','fldpi','fldlg2','fxch','fyl2x','fild','fsubrp','movapd','andpd','psubd','psllq','ucomisd','jnp','cmpnlepd','movlpd','unpcklpd','pextrw','orpd','addpd','subpd','mulpd','unpckhpd','cmpeqsd','xorpd','fldl2e','fmulp','faddp','fscale','fchs','fabs','fldln2','ftst','fcompp','frndint','fsub','f2xm1','fcomp','fmul','fsave','frstor','fxam','xlat','fadd','fucom','jp','fucompp','fcom',
--------------------unique_opcodes_length--------------------

233

--------------------unique_operands--------------------

'ebp','ebx','edi','esi','esp','addr','eax','APTR','[esp+addr]','ecx','ds:addr','cl','[esi+edi*1-addr]','n','o','e','[ecx+ebp*1]','[esp]','[ebx+addr]','[edi+ebx*1]','edx','[ecx]','[eax]','[ebp+eax*1+addr]','[esi+addr]','[esi]','al','[edx+addr]','[edx]','bl','[edi+addr]','dl','[ebx+esi*1]','[ebx]','[eax-addr]','[ecx*4+addr]','[eax+eax*1-addr]','[eax+ecx*1]','[ecx+ecx*2+addr]','[ecx+edx*8]','[ecx+edx*8+addr]','[eax+eax*2]','[eax*4+addr]','[ebp+addr]','[eax+esi*8+addr]','[eax+esi*8]','[ecx+addr]','[edi]','[esi*4+addr]','[eax+addr]','[edi*4+addr]','[ebp*4+addr]','[ebx*4+addr]','[ebx+eax*1+addr]','[ebx+edi*1+addr]','[ebx-addr]','[ebx+esi*1+addr]','[ebp-addr]','[edx+ebx*4]','[eax+esi*4]','xmm0','xmm1','[edx+esi*4]','[eax+edi*4]','[ebp+edi*1+addr]','1','[eax+ebx*4]','[ecx+eax*4]','[ebp+ecx*4+addr]','[esi+esi*2]','[esi+esi*2+addr]','[eax+eax*2+addr]','[edi+edi*2]','[edi+edi*2+addr]','[ecx*8+addr]','[eax+edx*1]','XMMAPTR','bh','[eax+ebp*4]','[ecx+ebp*4]','[ebx+ebp*4]','[ecx+ebx*4+addr]','[ecx+ebx*4]','[ebp+edi*4+addr]','[ecx+edi*4+addr]','[ecx+edi*4]','[edx+eax*4]','[eax+ecx*4]','[ecx+edi*1]','[eax+edi*1-addr]','[edi-addr]','cx','ax','bx','[eax+edi*1]','[ecx+eax*1-addr]','[eax+ecx*1-addr]','[edx+eax*1-addr]','[ebx+eax*1-addr]','[ebx+edi*1]','[edi+edi*1]','[ecx+ecx*1+addr]','[eax+edi*2]','[esi+edi*2+addr]','[edx+esi*1+addr]','[edi+eax*1]','movs','es:[edi]','ds:[esi]','[eax+eax*4]','[ecx+esi*1]','[edi+esi*1]','[ecx-addr]','[eax+ebx*1]','[ebp+ebp*2+addr]','[esp+edx*1+addr]','[esp+ebp*1+addr]','[eax+edi*1+addr]','[esi+ebx*1]','[esi+ebp*1]','[edx+ecx*4]','[ebx+ebx*2]','[ecx+edx*1]','[esi-addr]','[edx-addr]','ah','[ebp+esi*4+addr]','[ebp+ebx*1+addr]','[esi+edx*4+addr]','[edi+ebp*1]','[edx*4+addr]','dh','[edi+ecx*4+addr]','ch','[esi+edx*1]','[eax+edx*1-addr]','[eax+esi*1-addr]','[edx+edx*2]','[edi+eax*4+addr]','[edi+ecx*1-addr]','[edi+ecx*1]','[edi+ecx*1+addr]','[edi+edx*1-addr]','[edi+ebx*1-addr]','[ecx+ebx*1]','[edx+ecx*1]','[eax+ecx*1+addr]','[ebx+ecx*1-addr]','[edi+ebp*1-addr]','[eax+esi*1]','[ecx+ecx*2]','[edx+ecx*4+addr]','dx','[eax+ecx*4-addr]','[esi+edi*1]','[esi+eax*1-addr]','[esi+eax*1]','[ecx+esi*1+addr]','[esp+esi*4+addr]','[esp+ebx*1+addr]','[ebp+esi*1+addr]','[ebx+ebp*1+addr]','[esi+eax*2]','[ecx+ecx*4]','[eax+ebx*1+addr]','[eax+ebx*1-addr]','[esp+eax*1+addr]','[edi+ebp*1+addr]','[edi+esi*1+addr]','[eax+ebp*1+addr]','[edi+esi*1-addr]','[edx+eax*1+addr]','[edi+eax*1+addr]','[esp+ecx*1+addr]','[ecx+ebp*1+addr]','[ebp+edi*1-addr]','[esi+ecx*1+addr]','[esi+ecx*1]','[esi+ebp*1+addr]','[edx+ecx*4-addr]','[edi+ecx*4-addr]','[ebp*8+addr]','[ecx+eax*1+addr]','[esi+eax*2+addr]','[eax+esi*1+addr]','[esi+ecx*4+addr]','[eax*8+addr]','[edx+ebx*8]','[ebx+ebx*4]','[edx+edx*4+addr]','[esi+edi*4+addr]','[esi*8+addr]','[ecx+ebx*8+addr]','[ecx+ebx*8]','[edi+edi*4]','[eax+ebx*8+addr]','[eax+ebx*8]','[edx+edi*8+addr]','[edx+edi*8]','[ecx+eax*1]','[esp+ebx*4+addr]','[esp+edx*4+addr]','[esp+ecx*4+addr]','[esp+edi*4+addr]','[ebp+eax*4+addr]','[ecx+edx*4+addr]','[ecx+esi*4]','[ebp+ecx*1+addr]','[ecx+ebp*4+addr]','[eax+ebp*4+addr]','[eax+esi*4+addr]','[edi+ebx*4+addr]','[edi*8+addr]','[ebx+ecx*1]','[edx+eax*4+addr]','[edi+ebx*1+addr]','[edx+eax*1]','[esi+eax*1+addr]','[esp+edi*1+addr]','[esp+eax*4+addr]','[edx+edi*1]','[edx+edi*1+addr]','[ecx+edi*1+addr]','[ecx+edx*1+addr]','[ebx+edx*1-addr]','[esi+edi*1+addr]','[esi+eax*4]','[ebp+edx*1+addr]','[ebx+eax*1]','[esi+eax*4+addr]','[ebx+eax*4+addr]','xmm3','xmm2','[edx+edi*1-addr]','[eax+edx*1+addr]','[esi+ecx*4-addr]','[esi+ecx*4]','[edx+ebx*1]','xmm4','xmm5','[edi+edx*1]','[esp+ecx*1]','[esp+eax*1]','[esi+ebx*1+addr]','[esi+edx*1+addr]','[esi+edx*4]','[edi+edx*4+addr]','[ebx+edx*4]','[ebx+ecx*4]','[ebx+edx*4+addr]','[ebx+ecx*4+addr]','[ebx+edx*1+addr]','[ebx+eax*4]','[ebx+esi*4]','[edi+eax*4]','[ebp+ebp*1+addr]','[ebx+eax*4-addr]','[eax+ebx*4-addr]','[ebp+edx*4+addr]','[edi+ebp*4]','[esi+ebx*4]','[eax+edi*4-addr]','[edi+edi*1+addr]','[ebx+ebx*1]','[ecx+ebx*1-addr]','[esi+ebx*8]','[eax+eax*1+addr]','[ebp+eax*8-addr]','[edx+edx*1]','[esi+edi*4-addr]','[ebp+edx*4-addr]','[ecx+ecx*2-addr]','[eax+edx*4-addr]','[esi+edi*4]','[edi+edx*4]','[esi+eax*4-addr]','[edi+ecx*4]','[edi+eax*4-addr]','[ebp+eax*4-addr]','[ecx+ebx*4-addr]','[ebp+ebx*8-addr]','[edx+esi*4+addr]','[edi+ebx*4]','[ebx*8+addr]','[edi+eax*8]','[edx+ebp*4]','[edi+ebp*8-addr]','[esi+ebp*4-addr]','[eax+edx*4]','[ebx*8-addr]','[eax+ecx*4+addr]','[ebp+eax*1-addr]','[ebp+ecx*1-addr]','[esi*8-addr]','[eax+edi*4+addr]','[edi+esi*4+addr]','[ecx+esi*8]','[esi+esi*1]','[edi+esi*4]','[esi+esi*1+addr]','[eax+edx*4+addr]','[esi+ebp*4+addr]','[esi+ebp*4]','[ebp+edx*8+addr]','[ecx+edx*4]','[ebx+edi*4]','[edx+esi*1]','[ebp+esi*4-addr]','[ebp+ecx*4-addr]','[ebp+edi*4-addr]','xmm6','xmm7','[ebx+ecx*1+addr]','[ecx+edx*2]','[esi+edi*2]','[ecx+eax*8]','[esp+edx*4]','[esp+edi*4]','di','[ecx+ecx*1]','[eax+ebp*1]','[ecx+eax*4+addr]','[ecx+edi*2+addr]','[edx+ecx*2+addr]','[edx+ebx*1+addr]','[ebx+eax*2+addr]','[ebx+esi*2+addr]','[esp+edi*1]','[ebx+esi*1-addr]','[ecx+esi*1-addr]','[ebx+edi*1-addr]','[ecx+edx*1-addr]','[ebx+ebp*1-addr]','[ecx+edi*1-addr]','[ecx+ebp*1-addr]','[eax+ebp*1-addr]','[edx+esi*1-addr]','[edx+ebx*1-addr]','[esi+ebp*1-addr]','[ebx+ebp*1]','[esp+esi*1+addr]','[esi+esi*4]','[esp+esi*1]','[ebx+ebx*1+addr]','[esi+ebx*2+addr]','[esp+edx*4-addr]','[esp+ebp*4+addr]','[esp+ecx*4]','[ebp+eax*8+addr]','[esp+eax*8+addr]','[esp+ebx*8+addr]','[esp+esi*8+addr]','[esp+edi*8+addr]','[esp+ecx*8+addr]','[esp+ecx*4-addr]','[edi+eax*8+addr]','[esi+eax*8]','[esi+eax*8+addr]','[esi+ecx*1-addr]','[edx+ecx*1+addr]','[esi+ecx*2+addr]','[esi+ecx*2]','[ebp+edx*2+addr]','[edx*8+addr]','[ebp+esi*8+addr]','[ecx+esi*2]','[ecx+esi*2+addr]','[ecx+eax*2+addr]','[ecx+edi*2]','si','[ecx+eax*8+addr]','[ecx+edi*8+addr]','[ebx+edi*8]','[eax+edi*8]','[eax+edi*8+addr]','[esp+edx*1]','[edx+ebp*1]','[edx+ebp*1+addr]','[ecx+edi*4-addr]','[edi+ebp*4+addr]','[esi+ebp*2]','[edx+ebp*2]','[eax+ecx*2+addr]','[edi+esi*2+addr]','[esp+ecx*2+addr]','[esp+edx*2+addr]','[esp+edi*2+addr]','[edx+ecx*2]','[ebp+esi*2+addr]','[edx+ecx*2-addr]','[eax+ecx*2]','[ebx+edi*2]','[edi+edx*2+addr]','[ecx+ebx*1+addr]','[edi+eax*1-addr]','[edx+edx*4]','[edx+ebp*1-addr]','[eax+edx*2]','[ecx*4-addr]','[eax+edx*2+addr]','[ecx+edx*2+addr]','[eax*4-addr]','[esi+edx*2+addr]','[esi+ebx*4+addr]','[ebx+esi*4+addr]','[ebx+ebp*4+addr]','[edx+esi*8+addr]','[edx+ebp*8+addr]','[edx+ebp*8]','[edi+ebx*4-addr]','[ebx+edi*4-addr]','[esi+ebx*4-addr]','[ebx+esi*4-addr]','[ecx+eax*4-addr]','[eax+ebp*8+addr]','[ecx+ecx*8]','[esi+esi*8]','[edi+esi*8]','[edi+esi*8+addr]','[ebx+esi*8]','[ebx+ebx*8]','[eax+eax*1]','[edx+eax*2]','[edx+edi*4]','[edx+edi*4+addr]','[edi+ebp*2]','bp','[edi+edi*1-addr]','[edx+eax*8+addr]','[ecx+eax*2]','[esp+eax*2+addr]','[edx+edx*1+addr]','[ecx+edi*8]','[edx+esi*2]','[ecx+ebx*2]','[edx+ebx*2]','[ebp+ebx*2+addr]','[ebp+ecx*2+addr]','[edi+ecx*2+addr]','[eax+esi*2]','[edi+ebp*2+addr]','[ebp+eax*2+addr]','[eax+ebp*2]','[edx+edx*2+addr]','[ebx+edx*2]','[ebx+ebp*2]','[ebx+ebx*2+addr]','[esp+eax*1-addr]','[eax+ebx*4+addr]','stos','[edi+eax*2+addr]','[edi+ebx*2+addr]','[edi+eax*2]','[edi+edx*2]','[edx+edi*2]','jne','ret','jmp','jb','mov','ss','cs','ds','es','fs','gs','fs:addr','cmpxchg','[ecx*2-addr]','[eax*2-addr]','addr:addr','xchg','xmm10','fs:[esi]','[esp+eiz*4+addr]','[eiz*4+addr]','[edx+ebp*4+addr]','scas','xadd','[edi+ebx*2-addr]','[eax+ecx*8+addr]','[ebx+eax*8+addr]','FAPTR','[ebp+ebp*1-addr]','[ebp+ebx*2-addr]','[ebp+ebx*4-addr]','[ebp+ecx*2-addr]','[eax+ecx*2-addr]','[ebx+ecx*2]','or','and','inc','ymm1','ymm0','YMMAPTR','[ebp+esi*1-addr]','[eax+ebx*2]','call','[ebx+edx*1]','dec','[ecx+eax*2-addr]','[edi+ecx*2]','[ebp+edx*1-addr]','TAPTR','st(1)','st','st(0)','[edi+eax*2-addr]','ds:[ebx]',
--------------------unique_operands_length--------------------

509

--------------------opcodes and operands--------------------

[
'ebp','ebx','edi','esi','esp','addr','eax','APTR','[esp+addr]','ecx','ds:addr','cl','[esi+edi*1-addr]','n','o','e','[ecx+ebp*1]','[esp]','[ebx+addr]','[edi+ebx*1]','edx','[ecx]','[eax]','[ebp+eax*1+addr]','[esi+addr]','[esi]','al','[edx+addr]','[edx]','bl','[edi+addr]','dl','[ebx+esi*1]','[ebx]','[eax-addr]','[ecx*4+addr]','[eax+eax*1-addr]','[eax+ecx*1]','[ecx+ecx*2+addr]','[ecx+edx*8]','[ecx+edx*8+addr]','[eax+eax*2]','[eax*4+addr]','[ebp+addr]','[eax+esi*8+addr]','[eax+esi*8]','[ecx+addr]','[edi]','[esi*4+addr]','[eax+addr]','[edi*4+addr]','[ebp*4+addr]','[ebx*4+addr]','[ebx+eax*1+addr]','[ebx+edi*1+addr]','[ebx-addr]','[ebx+esi*1+addr]','[ebp-addr]','[edx+ebx*4]','[eax+esi*4]','xmm0','xmm1','[edx+esi*4]','[eax+edi*4]','[ebp+edi*1+addr]','1','[eax+ebx*4]','[ecx+eax*4]','[ebp+ecx*4+addr]','[esi+esi*2]','[esi+esi*2+addr]','[eax+eax*2+addr]','[edi+edi*2]','[edi+edi*2+addr]','[ecx*8+addr]','[eax+edx*1]','XMMAPTR','bh','[eax+ebp*4]','[ecx+ebp*4]','[ebx+ebp*4]','[ecx+ebx*4+addr]','[ecx+ebx*4]','[ebp+edi*4+addr]','[ecx+edi*4+addr]','[ecx+edi*4]','[edx+eax*4]','[eax+ecx*4]','[ecx+edi*1]','[eax+edi*1-addr]','[edi-addr]','cx','ax','bx','[eax+edi*1]','[ecx+eax*1-addr]','[eax+ecx*1-addr]','[edx+eax*1-addr]','[ebx+eax*1-addr]','[ebx+edi*1]','[edi+edi*1]','[ecx+ecx*1+addr]','[eax+edi*2]','[esi+edi*2+addr]','[edx+esi*1+addr]','[edi+eax*1]','movs','es:[edi]','ds:[esi]','[eax+eax*4]','[ecx+esi*1]','[edi+esi*1]','[ecx-addr]','[eax+ebx*1]','[ebp+ebp*2+addr]','[esp+edx*1+addr]','[esp+ebp*1+addr]','[eax+edi*1+addr]','[esi+ebx*1]','[esi+ebp*1]','[edx+ecx*4]','[ebx+ebx*2]','[ecx+edx*1]','[esi-addr]','[edx-addr]','ah','[ebp+esi*4+addr]','[ebp+ebx*1+addr]','[esi+edx*4+addr]','[edi+ebp*1]','[edx*4+addr]','dh','[edi+ecx*4+addr]','ch','[esi+edx*1]','[eax+edx*1-addr]','[eax+esi*1-addr]','[edx+edx*2]','[edi+eax*4+addr]','[edi+ecx*1-addr]','[edi+ecx*1]','[edi+ecx*1+addr]','[edi+edx*1-addr]','[edi+ebx*1-addr]','[ecx+ebx*1]','[edx+ecx*1]','[eax+ecx*1+addr]','[ebx+ecx*1-addr]','[edi+ebp*1-addr]','[eax+esi*1]','[ecx+ecx*2]','[edx+ecx*4+addr]','dx','[eax+ecx*4-addr]','[esi+edi*1]','[esi+eax*1-addr]','[esi+eax*1]','[ecx+esi*1+addr]','[esp+esi*4+addr]','[esp+ebx*1+addr]','[ebp+esi*1+addr]','[ebx+ebp*1+addr]','[esi+eax*2]','[ecx+ecx*4]','[eax+ebx*1+addr]','[eax+ebx*1-addr]','[esp+eax*1+addr]','[edi+ebp*1+addr]','[edi+esi*1+addr]','[eax+ebp*1+addr]','[edi+esi*1-addr]','[edx+eax*1+addr]','[edi+eax*1+addr]','[esp+ecx*1+addr]','[ecx+ebp*1+addr]','[ebp+edi*1-addr]','[esi+ecx*1+addr]','[esi+ecx*1]','[esi+ebp*1+addr]','[edx+ecx*4-addr]','[edi+ecx*4-addr]','[ebp*8+addr]','[ecx+eax*1+addr]','[esi+eax*2+addr]','[eax+esi*1+addr]','[esi+ecx*4+addr]','[eax*8+addr]','[edx+ebx*8]','[ebx+ebx*4]','[edx+edx*4+addr]','[esi+edi*4+addr]','[esi*8+addr]','[ecx+ebx*8+addr]','[ecx+ebx*8]','[edi+edi*4]','[eax+ebx*8+addr]','[eax+ebx*8]','[edx+edi*8+addr]','[edx+edi*8]','[ecx+eax*1]','[esp+ebx*4+addr]','[esp+edx*4+addr]','[esp+ecx*4+addr]','[esp+edi*4+addr]','[ebp+eax*4+addr]','[ecx+edx*4+addr]','[ecx+esi*4]','[ebp+ecx*1+addr]','[ecx+ebp*4+addr]','[eax+ebp*4+addr]','[eax+esi*4+addr]','[edi+ebx*4+addr]','[edi*8+addr]','[ebx+ecx*1]','[edx+eax*4+addr]','[edi+ebx*1+addr]','[edx+eax*1]','[esi+eax*1+addr]','[esp+edi*1+addr]','[esp+eax*4+addr]','[edx+edi*1]','[edx+edi*1+addr]','[ecx+edi*1+addr]','[ecx+edx*1+addr]','[ebx+edx*1-addr]','[esi+edi*1+addr]','[esi+eax*4]','[ebp+edx*1+addr]','[ebx+eax*1]','[esi+eax*4+addr]','[ebx+eax*4+addr]','xmm3','xmm2','[edx+edi*1-addr]','[eax+edx*1+addr]','[esi+ecx*4-addr]','[esi+ecx*4]','[edx+ebx*1]','xmm4','xmm5','[edi+edx*1]','[esp+ecx*1]','[esp+eax*1]','[esi+ebx*1+addr]','[esi+edx*1+addr]','[esi+edx*4]','[edi+edx*4+addr]','[ebx+edx*4]','[ebx+ecx*4]','[ebx+edx*4+addr]','[ebx+ecx*4+addr]','[ebx+edx*1+addr]','[ebx+eax*4]','[ebx+esi*4]','[edi+eax*4]','[ebp+ebp*1+addr]','[ebx+eax*4-addr]','[eax+ebx*4-addr]','[ebp+edx*4+addr]','[edi+ebp*4]','[esi+ebx*4]','[eax+edi*4-addr]','[edi+edi*1+addr]','[ebx+ebx*1]','[ecx+ebx*1-addr]','[esi+ebx*8]','[eax+eax*1+addr]','[ebp+eax*8-addr]','[edx+edx*1]','[esi+edi*4-addr]','[ebp+edx*4-addr]','[ecx+ecx*2-addr]','[eax+edx*4-addr]','[esi+edi*4]','[edi+edx*4]','[esi+eax*4-addr]','[edi+ecx*4]','[edi+eax*4-addr]','[ebp+eax*4-addr]','[ecx+ebx*4-addr]','[ebp+ebx*8-addr]','[edx+esi*4+addr]','[edi+ebx*4]','[ebx*8+addr]','[edi+eax*8]','[edx+ebp*4]','[edi+ebp*8-addr]','[esi+ebp*4-addr]','[eax+edx*4]','[ebx*8-addr]','[eax+ecx*4+addr]','[ebp+eax*1-addr]','[ebp+ecx*1-addr]','[esi*8-addr]','[eax+edi*4+addr]','[edi+esi*4+addr]','[ecx+esi*8]','[esi+esi*1]','[edi+esi*4]','[esi+esi*1+addr]','[eax+edx*4+addr]','[esi+ebp*4+addr]','[esi+ebp*4]','[ebp+edx*8+addr]','[ecx+edx*4]','[ebx+edi*4]','[edx+esi*1]','[ebp+esi*4-addr]','[ebp+ecx*4-addr]','[ebp+edi*4-addr]','xmm6','xmm7','[ebx+ecx*1+addr]','[ecx+edx*2]','[esi+edi*2]','[ecx+eax*8]','[esp+edx*4]','[esp+edi*4]','di','[ecx+ecx*1]','[eax+ebp*1]','[ecx+eax*4+addr]','[ecx+edi*2+addr]','[edx+ecx*2+addr]','[edx+ebx*1+addr]','[ebx+eax*2+addr]','[ebx+esi*2+addr]','[esp+edi*1]','[ebx+esi*1-addr]','[ecx+esi*1-addr]','[ebx+edi*1-addr]','[ecx+edx*1-addr]','[ebx+ebp*1-addr]','[ecx+edi*1-addr]','[ecx+ebp*1-addr]','[eax+ebp*1-addr]','[edx+esi*1-addr]','[edx+ebx*1-addr]','[esi+ebp*1-addr]','[ebx+ebp*1]','[esp+esi*1+addr]','[esi+esi*4]','[esp+esi*1]','[ebx+ebx*1+addr]','[esi+ebx*2+addr]','[esp+edx*4-addr]','[esp+ebp*4+addr]','[esp+ecx*4]','[ebp+eax*8+addr]','[esp+eax*8+addr]','[esp+ebx*8+addr]','[esp+esi*8+addr]','[esp+edi*8+addr]','[esp+ecx*8+addr]','[esp+ecx*4-addr]','[edi+eax*8+addr]','[esi+eax*8]','[esi+eax*8+addr]','[esi+ecx*1-addr]','[edx+ecx*1+addr]','[esi+ecx*2+addr]','[esi+ecx*2]','[ebp+edx*2+addr]','[edx*8+addr]','[ebp+esi*8+addr]','[ecx+esi*2]','[ecx+esi*2+addr]','[ecx+eax*2+addr]','[ecx+edi*2]','si','[ecx+eax*8+addr]','[ecx+edi*8+addr]','[ebx+edi*8]','[eax+edi*8]','[eax+edi*8+addr]','[esp+edx*1]','[edx+ebp*1]','[edx+ebp*1+addr]','[ecx+edi*4-addr]','[edi+ebp*4+addr]','[esi+ebp*2]','[edx+ebp*2]','[eax+ecx*2+addr]','[edi+esi*2+addr]','[esp+ecx*2+addr]','[esp+edx*2+addr]','[esp+edi*2+addr]','[edx+ecx*2]','[ebp+esi*2+addr]','[edx+ecx*2-addr]','[eax+ecx*2]','[ebx+edi*2]','[edi+edx*2+addr]','[ecx+ebx*1+addr]','[edi+eax*1-addr]','[edx+edx*4]','[edx+ebp*1-addr]','[eax+edx*2]','[ecx*4-addr]','[eax+edx*2+addr]','[ecx+edx*2+addr]','[eax*4-addr]','[esi+edx*2+addr]','[esi+ebx*4+addr]','[ebx+esi*4+addr]','[ebx+ebp*4+addr]','[edx+esi*8+addr]','[edx+ebp*8+addr]','[edx+ebp*8]','[edi+ebx*4-addr]','[ebx+edi*4-addr]','[esi+ebx*4-addr]','[ebx+esi*4-addr]','[ecx+eax*4-addr]','[eax+ebp*8+addr]','[ecx+ecx*8]','[esi+esi*8]','[edi+esi*8]','[edi+esi*8+addr]','[ebx+esi*8]','[ebx+ebx*8]','[eax+eax*1]','[edx+eax*2]','[edx+edi*4]','[edx+edi*4+addr]','[edi+ebp*2]','bp','[edi+edi*1-addr]','[edx+eax*8+addr]','[ecx+eax*2]','[esp+eax*2+addr]','[edx+edx*1+addr]','[ecx+edi*8]','[edx+esi*2]','[ecx+ebx*2]','[edx+ebx*2]','[ebp+ebx*2+addr]','[ebp+ecx*2+addr]','[edi+ecx*2+addr]','[eax+esi*2]','[edi+ebp*2+addr]','[ebp+eax*2+addr]','[eax+ebp*2]','[edx+edx*2+addr]','[ebx+edx*2]','[ebx+ebp*2]','[ebx+ebx*2+addr]','[esp+eax*1-addr]','[eax+ebx*4+addr]','stos','[edi+eax*2+addr]','[edi+ebx*2+addr]','[edi+eax*2]','[edi+edx*2]','[edx+edi*2]','jne','ret','jmp','jb','mov','ss','cs','ds','es','fs','gs','fs:addr','cmpxchg','[ecx*2-addr]','[eax*2-addr]','addr:addr','xchg','xmm10','fs:[esi]','[esp+eiz*4+addr]','[eiz*4+addr]','[edx+ebp*4+addr]','scas','xadd','[edi+ebx*2-addr]','[eax+ecx*8+addr]','[ebx+eax*8+addr]','FAPTR','[ebp+ebp*1-addr]','[ebp+ebx*2-addr]','[ebp+ebx*4-addr]','[ebp+ecx*2-addr]','[eax+ecx*2-addr]','[ebx+ecx*2]','or','and','inc','ymm1','ymm0','YMMAPTR','[ebp+esi*1-addr]','[eax+ebx*2]','call','[ebx+edx*1]','dec','[ecx+eax*2-addr]','[edi+ecx*2]','[ebp+edx*1-addr]','TAPTR','st(1)','st','st(0)','[edi+eax*2-addr]','ds:[ebx]','push','sub','cmp','je','test','add','jg','xor','setne','cmovne','pop','jle','lea','jl','int3','js','movsx','jae','ja','sbb','shl','jge','setg','movzx','bswap','cmovle','shr','not','sete','jns','neg','cvtsi2sd','divsd','movsd','fstp','mulsd','cvttsd2si','sar','cmovg','cmovl','cmove','movaps','movups','seta','cmovb','imul','cmovs','jbe','rep','bt','div','cmovbe','mul','cmovge','cmovns','setb','cmova','adc','cdq','idiv','movd','pshufd','movdqu','punpckldq','punpcklqdq','cmovae','pxor','pinsrw','punpcklbw','punpcklwd','pslld','por','setle','shld','setae','setbe','movq','rol','paddd','movdqa','psrld','shufps','andps','pshuflw','psrlq','pand','pshufhw','packuswb','pandn','xorps','seto','lahf','sahf','ror','psrad','psrlw','punpckhbw','punpckhwd','punpckhdq','shrd','setns','setl','cwde','setge','pcmpeqd','cvtss2sd','addsd','sets','packssdw','paddw','pcmpeqb','pmovmskb','bnd','int','data16','pushf','fnclex','lock','cpuid','xgetbv','fwait','nop','popf','vfrczpd','palignr','std','cld','in','movlhps','bsf','bsr','leave','pcmpistri','repnz','pinsrb','psrldq','jno','arpl','les','cmps','lds','jecxz','(bad)','cbw','hlt','cmc','fldz','clc','icebp','bts','fld','vxorps','vpcmpeqb','vpmovmskb','vzeroupper','vpcmpeqw','pcmpeqw','rcr','fnstsw','stmxcsr','ldmxcsr','fstcw','fldcw','stc','fst','fnstcw','fnstenv','fldenv','fistp','fstsw','fld1','fdivp','fldpi','fldlg2','fxch','fyl2x','fild','fsubrp','movapd','andpd','psubd','psllq','ucomisd','jnp','cmpnlepd','movlpd','unpcklpd','pextrw','orpd','addpd','subpd','mulpd','unpckhpd','cmpeqsd','xorpd','fldl2e','fmulp','faddp','fscale','fchs','fabs','fldln2','ftst','fcompp','frndint','fsub','f2xm1','fcomp','fmul','fsave','frstor','fxam','xlat','fadd','fucom','jp','fucompp','fcom',]

--------------------unique_ops_length--------------------

727

"""

ops = unique(operands + opcodes)
ops.sort()



"""
creating the list of words using unique_opcodes and unique_operands with sorting.
"""

"""
The first word is 'push'. It’s total count in the sentence is 1. 
Also, in the list of words above, its position is 1th from the starting . 
I’ll just update its vector and it will now be at the index that is residing in the sorted list. 
[0, 0, 0, 0, 0, 0,.....?....]
we see that push is at position 657
so we check the index of push in sorted list. 
"""
print("index of push : {}".format(ops.index('push'))) #prints 657

"""
creating a two dimensional array to hold the instructions vector representation

So for each sentence (instruction) we’ll create an array of zeros with the same length as unique_ops_length (724)
"""


sentence_count = len(instructions)
unique_ops_count = len(ops)

print("unique_ops_count : {}".format(unique_ops_count) )
print("sentence_count : {}".format(sentence_count))  

vector = [[0] * unique_ops_count for i in range(sentence_count)]

print(" Total documents (N): {}".format(sentence_count))
counts_opcodes = counts(opcodes)

print("Documents in which the word push appears (n): {}".format(counts_opcodes['push']))
print("Number of times the word push appears in the first sentence: {}".format(instructions[0].count('push')))
print("Number of words in the first sentence: {}".format(len(instructions[0].split(' '))))
print("Term Frequency(TF) = {}".format(instructions[0].count('push')))
print("Inverse Document Frequency(IDF) = log({}/{}) = {}".format(sentence_count,counts_opcodes['push'], math.log(sentence_count,float(counts_opcodes['push']))))
print("TF-IDF value = 1 * log(N/n) = {}".format(math.log(sentence_count,float(counts_opcodes['push']))))

# for i in range(sentence_count):
#     instruction = instructions[i]
#     words = instruction.split(' ')
#     for word in words:
#         vector[i][ops.index(word)]+=1




# arr = np.array(vector)
# for i in range(2):
#     print(vector[i])
#     for k in nextIndex(1, vector[i]):
#         print(k)

"""
index of push : 657
unique_ops_count : 727
sentence_count : 176996
 Total documents (N): 176996
Documents in which the word push appears (n): 31641
Number of times the word push appears in the first sentence: 1
Number of words in the first sentence: 2
Term Frequency(TF) = 1
Inverse Document Frequency(IDF) = log(176996/31641) = 1.1661492622865435
TF-IDF value = 1 * log(N/n) = 1.1661492622865435
"""