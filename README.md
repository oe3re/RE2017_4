# RE2017_4
Otkrivanje/skrivanje tajne poruke


Projekat 4 - otkrivanje/skrivanje tajne poruke
Napisati program kojim se vrži otkrivanje tajne poruke koja se nalazi u slici i zapisuje je u
novi PGMA file, a zatim u ulaznu sliku sakriva proizvoljnu novu poruku.
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 

U slikama koje su zapisane u 8-bitnom formatu, mogu se izdvojiti pojedine bitske ravni. 
Pokazuje se da na izgled slike dominantno utiče nekoliko najviših bitskih ravni, dok najniºe ravni jako malo, moglo bi se reći i neprimetno, utiču na sam izgled slike. Zbog ove osobine, u poslednju bitsku ravan moguće je sakriti tajnu poruku koja se
posmatranjem cele slike ne može primetiti, ali se može dobiti izdvajanjem najniže bitske ravni
iz slike.

Ukoliko tajna poruka/slika sadrži više nivoa sivog (nije crno-bela), njena bitska ravan najveće
težine umeće se kao bitska ravan najmanje težine u sliku u koju se sakriva poruka. Ukoliko
je slika crno-bela sasvim je svejedno koja se bitska ravan tajne poruke izdvaja, jer su sve identi£ne.
Nakon izdvajanja najniže bitske ravni, a pre zapisivanja poruke u izlazni PGMA file,
potrebno je sve elemente pomnožiti sa 255 kako bi se ostvario što bolji kontrast.


Više na: http://tnt.etf.bg.ac.rs/~oe3re/Projekti/Projekti_2017.pdf
