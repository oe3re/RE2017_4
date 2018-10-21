INCLUDE Irvine32.inc
INCLUDE macros.inc

BUFFER_SIZE = 256 * 256 * 20

.data
buffer BYTE BUFFER_SIZE DUP(? );Bafer u koji se ubacuje ulazna datoteka - slika iz koje se treba izvuci tajna poruka.
buffer2 BYTE BUFFER_SIZE DUP(? );Bafer u koji se ubacuje ulazna datoteka - slika koja se ubacuje kao tajna poruka u prethodnu sliku. 

infilename    BYTE 80 DUP(0)
outfilename    BYTE 80 DUP(0)

fileHandle  HANDLE ?

stringLength DWORD ?;Duzina slike sa tajnom porukom.
stringLength2 DWORD ?;Duzina slike koja je tajna poruka.

outBuffer BYTE BUFFER_SIZE DUP(? );Bafer u koji se smesta tajna poruka izvucena iz bafera buffer.
outBuffer7 BYTE BUFFER_SIZE DUP(? );Bafer u koji se smesta sedma bitska ravan iz bafera buffer2.
outBuffersifra BYTE BUFFER_SIZE DUP(? );Bafer u koji se smesta slika iz bafera buffer, 
										;izmenjenog tako da mu je najniza bitska ravan sedma bitska ravan iz bafera outBaffer7.

counter1 DWORD 0;Brojac koji broji do 3 u proceduri pri prepisivanju zaglavlja datoteke.
counter22 DWORD 0;Brojac koji broji duzinu zaglavlja datoteke. 
counter2 DWORD 0;Vrednost brojaca counter22 se prepisuje u counter2 u proceduri proccess2,
				;da bi se sacuvala duzina zaglavlja buffer2 (ista kao i kod outBuffer7),
				;jer na kraju procedure u counter22 upisuje se 0.
				;Inkrementiranjem njega u sledecoj proceduri se pristupa sadrzaju datoteke posle zaglavlja.
				

pom4 DWORD ?;Pomocna promenljiva u koju se cuva vrednost eax registra.
pom5 DWORD ?;Pomocna promenljiva u koju se cuva vrednost eax registra.
pom6 DWORD ?;Pomocna promenljiva u koju se cuva vrednost eax registra.


.code


row_copy_paste PROC
;Procedura za prepisivanje reda u izlazni bafer:

    lodsb               ;Ako je prvi karakter u redu # to znaci da je taj red komentar,
	stosb               ;sto znaci da se taj red samo prepisuje karakter po karakter u
	dec ecx             ;izlazni bafer, a counter1 se ne uvecava. U slucaju kad prvi karakter nije #
	inc counter22		;counter1 se povecava. U ovu proceduru ce se dolaziti dok se ovde, u proceduri, counter1 ne uveca na 3
	cmp eax, '#'        ;jer postoje 3 reda zaglavlja ne racunajuci komentare (zbog toga se i ne uvecava brojac kad prepisujemo komentar).
	je paste            ;Prepisuju se tri reda zaglavlja jer sadrzaj slike koja je u pgm formatu izgleda:
	inc counter1          ;P2 ;prvi red
paste:                    ;broj redova  broj kolona  ;drugi red
    inc counter22		  ;maksimalna vrednost pixela  ;treci red  ;pri cemu se komentar moze naci izmedju svakog od ova tri reda
	lodsb               ;counter22 se inkrementira pri ucitavanju svakog znaka. 				 
	stosb               ;counter22 ce po zavrsetku ove procedure prebrojati koliko je znakova bilo u zaglavlju. 
	cmp eax, 0ah        ;0ah je oznaka za kraj reda, kad se u eax ucita 0ah skace se na endProc - kraj procedure.
	je endProc          
	loop paste          ;Pri svakom povratku na paste, ecx se dekrementira, naredba dec ecx je potrebna jer je jedno ucitavanje van petlje.
endProc:                
    ret					;Povratak na mesto sa kog je pozvana ova procedura.
row_copy_paste ENDP


proccess PROC
	;Procedura za obradu ulazne datoteke:
	;Izdvaja se najniza bitska ravan iz datoteke jer je u njoj sakrivena poruka.
	cld
    mov esi, OFFSET buffer ;U buffer je ucitana slika iz koje treba izvuci sakrivenu poruku (najnizu bitsku ravan).
	mov edi, OFFSET outBuffer ;U outBuffer se upisuje izvucena poruka iz buffer-a.
	mov ecx, LENGTHOF buffer ;brojac za petlju

copy:
	;Petlja kojom se prepisuje zaglavlje ulazne datoteke u izlaznu:
    cmp counter1, 3
	je move_on ; U proceduru row_copy_paste ide se dok counter1 ne postane 3, kad postane, skace se na move_on.
    call row_copy_paste
	loop copy

move_on:
    mov edx, esi ;Pamti se pocetni polozaj broja unutar stringa.

loop1:
	;Petlja se vrti dokle god je procitani karakter cifra, u suprotnom se skace na notDigit.
	lodsb               ;Pri svakom ponovnom dolasku na loop1, ecx se dekrementira, i oznacava preostalu duzinu bafera. 
	call IsDigit        
	jnz notDigit        
	loop loop1          
	jmp finish          ;Ako je kraj bafera zavrsi obradu.

notDigit:
    push esi            
	sub esi, edx        
	cmp esi, 1          ;U slucaju dva uzastopna karaktera koji nisu cifre (razmak + novi red) 
	jne compare         
	stosb               ;prepisuje se procitani karakter i		
	pop esi           
	loop move_on        ;vraca se na move_on.
	jmp finish          ;(ako je kraj bafera zavrsi obradu)

compare:				;Ukoliko je bilo cifri, umesto ispisivanja poslednjeg procitanog karaktera dolazi se ovde, ocitava se broj.
    push ecx            ;Stavljaju se na stek vrednosti ecx i eax jer su ti registri potrebni za dalji rad.
	push eax            
	mov ecx, esi        ;U ecx se prebacuje broj cifara vrednosti pixela.
	call ParseDecimal32 ;Konvertuje se string u decimalni broj.
	and eax, 01h        ;and 01h je maska kojom kao rezultat ostaje samo najniza bitska ravan.
	jnz one             ;Ako je rezultat razlicit od nule, skace se na labelu one.
	mov eax, '0'        ;Ako se ne skoci, rezultat je 0.
	stosb               ;Ispisuje se u izlazni bafer 0.
	jmp stek            ;Skace se na labelu stek

one:					;da se preskoci ispis jedinice.
    mov eax, '2'        ;Tacnije, umesto jedinice ispisuje se 255 da bi se dobilo na kontrastu.
	stosb               
	mov eax, '5'
	stosb
	stosb
	
stek:
	pop eax             ;Skida se sa steka prethodno stavljena vrednost eax
	stosb               ;i upisuje se u izlazni bafer (to je char koji nije bio cifra).
    pop ecx             ;Skidaju se vrednosti registara ecx i esi sa steka, kako bi se nastavilo normalnim tokom.
	pop esi             
	loop move_on        ;Ceo proces se ponavlja dok se ne dodje do kraja bafera. Svakim ponovnim ulaskom u petlju, ecx se dekrementira.

finish:
	mov counter1, 0	;Brojac se resetuje da bi ponovo mogla da se koristi ista procedura.
	mov counter22, 0 ;Brojac se resetuje da bi ponovo mogla da se koristi ista procedura.
	ret                 ;Povratak na mesto sa kog je pozvana ova procedura.
proccess ENDP


proccess2 PROC
	;Procedura za obradu ulazne datoteke
	;Iz datoteke se izdvaja najvisa (sedma) bitska ravan, 
	;koja ce u proceduri proccess3 biti ubacena u datoteku koja je ucitana pre ove datoteke.
	;Struktura procedure proccess2 je veoma slicna proceduri proccess, 
	;tako da ce biti komentarisane samo stvari koje su drugacije nego u proceduri proccess.
    cld
    mov esi, OFFSET buffer2 
	mov edi, OFFSET outBuffer7 
	mov ecx, LENGTHOF buffer2 
		
copy2:
    cmp counter1, 3
	je move_on2
    call row_copy_paste
	loop copy2

move_on2:
    mov edx, esi 

loop2:
	lodsb                
	call IsDigit        
	jnz notDigit2        
	loop loop2          
	jmp finish2          

notDigit2:
    push esi            
	sub esi, edx        
	cmp esi, 1          
	jne compare2         
	stosb               
	pop esi             
	loop move_on2        
	jmp finish2         

compare2:
    push ecx            
	push eax          
	mov ecx, esi        
	call ParseDecimal32 
	and eax, 80h         ;and 80h je maska takva da u rezultatu su svi biti osim sedmog nula, 
	jz zero2             ;a sedmi bit rezultata je sedmi bit eax. Ako je on nula skace se na zero2
	mov eax, '1'         ;U suprotnom, ispisuje se 1.
	stosb               	              
	jmp stek2            ;Preskace se ispis 0.

zero2:
    mov eax, '0'         ;Ispisuje se 0.
	stosb               
	            
stek2:
	pop eax             
	stosb 
    pop ecx         
	pop esi             
	loop move_on2        

finish2:
	mov counter1, 0;Brojac se resetuje da bi ponovo mogla da se koristi ista procedura.
	mov eax, counter22;Vrednost iz coutera22 se prepisuje u counter2 da bi bila sacuvana
	mov counter2, eax;jer counter22 mora da se resetuje.
	mov counter22, 0;Brojac se resetuje da bi ponovo mogla da se koristi ista procedura.
	ret                 
proccess2 ENDP


isp1 PROC
	push eax			;Poslednja ucitana vrednost (razmak) cuva se na steku dok ne dodje vreme da se ispise.
	mov eax, pom4
	and eax, 254		;Brise se najnizi bit - postavlja se na nulu.
	mov pom4, eax		;Vrednost eax cuva se u pom4.
	mov eax, counter2	;Kad se prvi put udje u ovu proceduru, outBuffer7[counter2] je prvi broj (0 ili 1) posle zaglavlja u tom baferu.
	xor edx, edx		;edx=0
	mov dl, outBuffer7[eax] ;U dl je 30 ili 31 jer je to ASCII kod za 0 i 1. 
	and dl, 01h				;Sada je u dl 0 ili 1.
	mov eax, edx
	add eax, pom4;Sada je u eax piksel u kome je na najnizem bitu smestena vrednost najviseg bita odgovarajuceg piksela slike koja se sakriva.
	stosb		; I ta vrednost se ispisuje.
	pop eax
	stosb		;Ispisuje se razmak.
	inc counter2 ;Vrednost brojaca se uvecava za 2 jer u baferu outBuffer7 izmedju svaka dva broja ima razmak, a nama trebaju samo brojevi.
	inc counter2
	dec ecx		;U proceduri iz koje smo dosli smo ucitali 2 karaktera, a postojala je samo jedna petlja, pa je neophodno da ecx dekrementiramo.
	ret
isp1 ENDP

isp2 PROC
	push eax
	mov eax, pom4	;Prva ucitana cifra se odmah ispisuje.
	stosb
	mov eax, pom5	;Za drugu ucitanu cifru vazi isti postupak kao za prvu cifru u proceduri isp1.
	and eax, 254
	mov pom5, eax
	mov eax, counter2
	xor edx, edx
	mov dl, outBuffer7[eax]
	and dl, 01h
	mov eax, edx
	add eax, pom5
	stosb
	pop eax
	stosb
	inc counter2
	inc counter2
	dec ecx		;Ovde se ecx dekrementira dva puta jer smo ucitali 3 karaktera, a imamo samo jednu petlju.
	dec ecx
	ret
isp2 ENDP

isp3 PROC
push eax
	mov eax, pom4	;Prva ucitana cifra se odmah ispisuje.
	stosb
	mov eax, pom5	;Druga ucitana cifra se odmah ispisuje.
	stosb
	mov eax, pom6	;Za trecu ucitanu cifru vazi isti postupak kao za prvu cifru u proceduri isp1.
	and eax, 254
	mov pom6, eax
	mov eax, counter2
	xor edx, edx
	mov dl, outBuffer7[eax]
	and dl, 01h
	mov eax, edx
	add eax, pom6
	stosb
	pop eax
	stosb
	inc counter2
	inc counter2
	dec ecx		;ecx se dekrementira 3 puta jer smo ucitali 4 karaktera, a imamo samo jednu petlju.
	dec ecx
	dec ecx
	ret
isp3 ENDP


proccess3 PROC
	;Procedura u kojoj se najvisa bitska ravan izvucena u proceduri proccess2 ubacuje 
	;kao najniza bitska ravan na mesto sifre koja je otkrivena u proceduri proccess
    cld
    mov esi, OFFSET buffer 
	mov edi, OFFSET outBuffersifra 
	mov ecx, LENGTHOF buffer 

copy3:
    cmp counter1, 3
	je move_on3
    call row_copy_paste
	loop copy3

move_on3:
    mov edx, esi 
	
loop13:
	lodsb          ;Ucitava se karakter.   
	call IsDigit   ;Proverava se da li je cifra.
	jnz notDigit33 ;Skace se ako je ucitan karakter koji nije cifra, ili ako su ucitane 3 cifre pa razmak.       
	mov pom4, eax  ;U pom4 se cuva prva ucitana cifra.
	lodsb		   ;Ucitava se naredni karakter.
	call IsDigit   ;Ispituje se da li je cifra.
	jnz notDigit31 ;Skace se ako je ucitana jedna cifra pa razmak.
	mov pom5, eax  ;U pom5 se cuva druga ucitana cifra.
	lodsb		   ;Ucitava se sledeci karakter.
	call IsDigit   ;Ispituje se da li je cifra.
	jnz notDigit32 ;Skace se ako su ucitane dve cifre i razmak.
	mov pom6, eax  ;U pom6 se cuva treca ucitana cifra
	loop loop13    ;U slucaju da su ucitane 3 cifre, sledeci karaktrer nije cifra sigurno jer je najveca vrednost piksela 255.
	jmp finish3         

notDigit31:
    call isp1		;Ispis jedne cifre i razmaka.
	loop move_on3

notDigit32:  
	call isp2		;Ispis dve cifre i razmaka.
	loop move_on3


notDigit33:
    push esi            
	sub esi, edx        
	cmp esi, 1          
	jne ispis3         
	stosb           ;Ispis novog reda (jer on dolazi posle razmaka).    
	pop esi             
	loop move_on3        
	jmp finish3          

ispis3:				;Ispis tri cifre i razmaka.
    call isp3
	pop esi
	loop move_on3

finish3:
	ret
proccess3 ENDP


main PROC;Glavni program

;Korisnik upisuje ime ulazne datoteke, sliku iz koje se otkriva tajna poruka i u koju se ubacuje neka druga poruka/slika:
	mWrite "Ime ulazne datoteke, slike iz koje se otkriva tajna poruka i u koju se ubacuje neka druga poruka/slika?: "
	mov	edx, OFFSET infilename
	mov	ecx, SIZEOF infilename
	call ReadString

;Otvoranje datoteke:
	mov	edx, OFFSET infilename
	call	OpenInputFile
	mov	fileHandle, eax

;Proveravanje da li ima gresaka:
	cmp	eax, INVALID_HANDLE_VALUE ;Da li postoji greska pri otvaranju datoteke?
	jne	file_ok_in ;Ako nema gresaka, skoci.
	mWrite <"Greska prilikom otvaranja ulazne datoteke.", 0dh, 0ah>
	jmp	quit ;Ako ima gresaka, zavrsi program.

file_ok_in :
	;Citanje fajla u bafer:
	mov	edx, OFFSET buffer
	mov	ecx, BUFFER_SIZE
	call	ReadFromFile
	jnc	check_buffer_size ;Proveravanje da li postoji greske pri citanju. Ako ne postoji, skoci.
	mWrite "Greska u citanju." ;U suprotnom ispisuje se da postoji greska i zatvara se fajl.
	call	WriteWindowsMsg
	jmp	close_file

;Proveravanje da li je bafer dovoljno veliki:
check_buffer_size :
	cmp	eax, BUFFER_SIZE ;Provera da li je bafer dovoljno veliki.
	jbe	buf_size_ok ;Ako jeste, skoci.
	mWrite <"Greska: bafer nije dovoljno veliki", 0dh, 0ah>;Ako nije, ispisi gresku
	jmp	quit;i zavrsi program.

buf_size_ok :
	mov	buffer[eax], 0 ;Ubacivanje terminatora 0.
	mWrite "Velicina datoteke: " 
	mov stringLength, eax
	call	WriteDec;Ispisivanje koliko je velika datoteka.
	call	Crlf

;Zatvaranje ulaznog fajla:
close_file :
	mov	eax, fileHandle
	call	CloseFile

;Korisnik upisuje ime ulazne datoteke, slike koja se sakriva u prethodno ucitanu sliku iz koje se procitala skrivena poruka: 
	mWrite "Ime ulazne datoteke, slike koja se sakriva u prethodno ucitanu sliku?: "
	mov	edx, OFFSET infilename
	mov	ecx, SIZEOF infilename
	call ReadString

;Otvoranje datoteke:
	mov	edx, OFFSET infilename
	call	OpenInputFile
	mov	fileHandle, eax

;Proveravanje da li ima gresaka:
	cmp	eax, INVALID_HANDLE_VALUE ;Da li postoji greska pri otvaranju datoteke?
	jne	file_ok_in1 ;Ako nema gresaka skoci.
	mWrite <"Greska prilikom otvaranja ulazne datoteke.", 0dh, 0ah>
	jmp	quit ;Ako ima gresaka, zavrsi program.

file_ok_in1 :
	;Citanje fajla u bafer:
	mov	edx, OFFSET buffer2
	mov	ecx, BUFFER_SIZE
	call	ReadFromFile
	jnc	check_buffer_size1 ;Proveravanje da li postoji greske pri citanju. Ako ne postoji, skoci.
	mWrite "Greska u citanju." ;U suprotnom ispisuje se da postoji greska i zatvara fajl.
	call	WriteWindowsMsg
	jmp	close_file1

;Proveravanje da li je bafer dovoljno veliki:
check_buffer_size1 :
	cmp	eax, BUFFER_SIZE ;Provera da li je bafer dovoljno veliki.
	jbe	buf_size_ok1 ;Ako jeste, skoci.
	mWrite <"Greska: bafer nije dovoljno veliki", 0dh, 0ah>;Ako nije, ispisi gresku
	jmp	quit;i zavrsi program.

buf_size_ok1 :
	mov	buffer2[eax], 0 ;Ubacivanje terminatora 0
	mWrite "Velicina datoteke: "
	mov stringLength2, eax
	call	WriteDec;ispisivanje koliko je velika datoteka.
	call	Crlf

;Zatvaranje ulaznog fajla:
close_file1 :
	mov	eax, fileHandle
	call	CloseFile
	

	call proccess;Izvlacenje tajne poruke iz datoteke koja je smestena u buffer. Tajna poruka se smesta u outBuffer

	call proccess2;Pravljenje tajne poruke koja ce se smestiti u ulaznu datoteku koja je bila ucitana u buffer.
	;Izvlacenje sedme bitske ravni iz slike koja je smestena u buffer2. Sedma bitska ravan(tajna poruka/slika) smesta se u outBuffer7.


;Korisnik unosi naziv izlazne datoteke, datoteke u koju je smestena otkrivena tajna poruka:
	mWrite "Ime datoteke u koju se smesta otkrivena tajna poruka?: "
	mov	edx, OFFSET outfilename
	mov	ecx, SIZEOF outfilename
	call	ReadString

;Pravljenje izlazne datoteke:
	mov	edx, OFFSET outfilename
	call	CreateOutputFile
	mov	fileHandle, eax
	
;Proveravanje da li ima gresaka:
	cmp	eax, INVALID_HANDLE_VALUE;Da li ima greske prilikom pravljenja izlazne datoteke?
	jne	file_ok_out ;Ako nema greske, skoci.
	mWrite <"Greska prilikom pravljenja izlazne datoteke.", 0dh, 0ah>;Ako ima greske, ispisi poruku
	jmp	quit ;i zatvori program.

file_ok_out :
	;Ispisivanje bafera u izlaznu datoteku.
	mov	eax, fileHandle
	mov	edx, OFFSET outBuffer
	mov	ecx, LENGTHOF outBuffer
	call	WriteToFile
	mov	eax, fileHandle
	call	CloseFile

	call proccess3;Smestanje tajne poruke (sedma bitska ravan slike) koja je izvucena u proceduri proccess2 
	;u sliku iz koje je u proceduri proccess otkrivena tajna poruka. Slika u slici se smesta u outBuffersifra


;Korisnik unosi naziv izlazne datoteke, datoteke u koju se smestena slika u kojoj je skrivena slika:
	mWrite "Ime izlazne datoteke, slike u koju je sakrivena druga slika?: "
	mov	edx, OFFSET outfilename
	mov	ecx, SIZEOF outfilename
	call	ReadString

;Pravljenje izlazne datoteke:
	mov	edx, OFFSET outfilename
	call	CreateOutputFile
	mov	fileHandle, eax

;Proveravanje da li ima gresaka:
	cmp	eax, INVALID_HANDLE_VALUE;Da li ima greske prilikom pravljenja izlazne datoteke?
	jne	file_ok_out2 ;Ako nema greske, skoci.
	mWrite <"Greska prilikom pravljenja izlazne datoteke.", 0dh, 0ah>;Ako ima greske, ispisi poruku
	jmp	quit;i zatvori program.

file_ok_out2 :
	;Ispisivanje bafera u izlaznu datoteku
	mov	eax, fileHandle
	mov	edx, OFFSET outBuffersifra
	mov	ecx, LENGTHOF outBuffersifra
	call	WriteToFile
	mov	eax, fileHandle
	call	CloseFile


;kraj programa
quit : 
	exit
	main ENDP

END main

