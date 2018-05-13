# Opis projektu

Projekt jest realizacją tematu nr 4: *"Analizator komunikacji sieci bezprzedowodych IEEE 802.11/Wi-Fi"*.

Analizowane są tylko nagłówki ramek IEEE 802.11 w celu ustalenia nadawcy, odbiorcy oraz pośredniczącego punktu dostępowego (AP) pakietu.

Po uruchomieniu program wypisuje na standardowe wyjście informacje o tym, jakie stacje się ze sobą komunikują oraz listę stacji których ruch obsługiwał dany punkt dostępowy.
Zliczana jest także liczba pakietów wysłanych pomiędzy każdą parą stacji.

Pakiety o błędnej sumie kontrolnej są ignorowane.

## Wymagane zależności
Kompilator zgodny z **C++17**.

**libpcap** w wersji *dev*.

**CMake 3.9** (prawdopodobnie zadziała też na starszym, można spróbować obniżyć wymaganą wersję w pierwszej linii pliku *CMakeLists.txt*).

## Kompilacja
```
cmake .
make
```

## Uruchomienie
```
sudo sh on.sh <nazwa_interfejsu_bezprzewodowego>
sudo WiFiSniffer <nazwa_interfejsu_bezprzewodowego>
sudo sh off.sh <nazwa_interfejsu_bezprzewodowego>
```

Skrypty *on.sh* i *off.sh* służą odpowiednio do włączania i wyłączania w interfejsie sieciowym **trybu monitor**,
który sprawia, że odbierane ramki IEEE 802.11 nie są konwertowane na ramki Ethernet.
Jest to niezbędne do poprawnego działania programu.

## Opis plików źródłowych
**Communication.h** - klasa przechowująca informacje dotyczące komunikacji pomiędzy dwoma stacjami.

**Define.h** - zawiera deklaracje stałych oraz struktur używanych w programie.

**ErrorCheckUtils.h** - zawiera makra automatyzujące sprawdzanie poprawności wykonania funkcji.

**MacAddress.h** - klasa reprezentująca pojedynczy adres MAC.

**Main.cpp** - główna pętla sterująca programu.

**TrafficAnalyzer.h** - klasa odpowiedzialna za analizowanie odbieranych pakietów i generowanie statystyk.

**Util.h** - zawiera funkcje pomocnicze dotyczące operacji na bitach, kontenerach i obliczania CRC-32 oraz haszy.