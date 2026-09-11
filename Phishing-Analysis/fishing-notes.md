# Message-ID — wyjaśnienie

---

## Czym jest Message-ID?

**Message-ID** to unikalny identyfikator nadawany każdej wiadomości e-mail, w formacie:

```
<losowy-ciąg-znaków@domena-lub-serwer>
```

Część po `@` to **nazwa serwera pocztowego, który wygenerował ten konkretny Message-ID** — nie zawsze jest to serwer atakującego.

---

## Ważne: Message-ID NIE zawsze pokazuje prawdziwego nadawcę

To częsty błąd w analizie phishingu — założenie, że domena w Message-ID to "prawdziwy" serwer, z którego wysłano maila.

W rzeczywistości Message-ID może zostać **nadpisany** (nadany na nowo) przez dowolny serwer pocztowy, przez który wiadomość przechodzi po drodze — w tym:

- serwer nadawcy (oryginalny, najczęstszy przypadek)
- serwer pośredniczący / bramkę antyspamową
- **serwer odbiorcy** — jeśli system pocztowy odbiorcy (np. Microsoft 365 z Exchange Online Protection) przetwarza wiadomość i nadpisuje jej Message-ID

**Przykład z naszej analizy (sample-681):**

```
Message-ID: <79f98a45-df69-4dba-a7f6-4efdad5a9cb1@VI1EUR06FT042.eop-eur06.prod.protection.outlook.com>
```

`eop-eur06.prod.protection.outlook.com` to domena **Exchange Online Protection** (usługa antyspamowa Microsoft 365). To niekoniecznie oznacza, że atakujący wysyłał maila z infrastruktury Microsoftu — równie prawdopodobne (a często bardziej prawdopodobne), że to **skrzynka odbiorcy** korzysta z Microsoft 365, i to jej serwer nadał ten Message-ID podczas odbierania wiadomości.

---

## Które nagłówki są bardziej wiarygodne?

Jeśli chcesz znaleźć prawdziwe pochodzenie wiadomości, Message-ID nie jest najlepszym źródłem. Lepiej sprawdzić:

| Nagłówek | Co pokazuje |
|---|---|
| **Received** (cały łańcuch) | Historia serwerów, przez które wiadomość przeszła — czytaj **od dołu do góry** (najstarszy hop na dole) |
| **SPF / DKIM / DMARC** | Wyniki uwierzytelniania — czy serwer nadawcy był autoryzowany do wysyłki w imieniu danej domeny |
| **X-Sender-IP** | Często (choć nie zawsze) faktyczny adres IP, z którego nadano wiadomość |

---

## SPF, DKIM, DMARC — wyjaśnienie

### SPF (Sender Policy Framework)

Rekord DNS domeny mówiący: **"te serwery/adresy IP są autoryzowane do wysyłania maili w imieniu tej domeny."**

Jak działa: odbierający serwer sprawdza rekord SPF domeny z `MAIL FROM` (envelope sender) i porównuje go z IP, z którego faktycznie przyszła wiadomość.

Wynik: **Pass** (IP autoryzowane) / **Fail** (IP nieautoryzowane — silny sygnał spoofingu) / SoftFail / Neutral / None.

### DKIM (DomainKeys Identified Mail)

**Cyfrowy podpis** dodawany do wiadomości przez serwer nadawcy, weryfikowany kluczem publicznym opublikowanym w DNS domeny.

Jak działa: serwer nadawcy podpisuje określone nagłówki i treść maila swoim prywatnym kluczem; odbiorca weryfikuje ten podpis kluczem publicznym pobranym z DNS.

Wynik: **Pass** (podpis prawidłowy, treść niezmieniona po drodze) / **Fail** (podpis nieprawidłowy lub treść zmodyfikowana).

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

**Polityka domeny** mówiąca odbiorcy, co zrobić, jeśli SPF i/lub DKIM zawiodą — opiera się na wynikach obu powyższych.

Polityki: `none` (nic nie rób, tylko raportuj) / `quarantine` (wyślij do spamu) / `reject` (odrzuć całkowicie).

Dodatkowy wymóg — **alignment**: domena w nagłówku `From` musi się zgadzać z domeną zweryfikowaną przez SPF/DKIM, żeby DMARC uznał wiadomość za w pełni uwierzytelnioną.

### Gdzie to znaleźć w surowym mailu?

Odbierający serwer zwykle dodaje własny nagłówek podsumowujący wyniki:

```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com;
       spf=pass (google.com: domain of ... designates ... as permitted sender);
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
```

### Dlaczego to ważne w analizie phishingu?

Jeśli SPF/DKIM/DMARC = **Fail**, to silny sygnał, że nadawca sfałszował (podszył się pod) cudzą domenę.

**Ale uwaga:** atakujący często rejestrują **własne** domeny (jak `seguro-autoo.com` w naszej analizie) i poprawnie konfigurują dla nich SPF/DKIM/DMARC — wtedy uwierzytelnianie da **Pass**, mimo że to nadal phishing! Pozytywny wynik oznacza tylko, że *"domena w nagłówku From faktycznie wysłała tę wiadomość"* — **nie** oznacza, że ta domena jest zaufana czy legalna.

### Przykład z naszej analizy (sample-681) — dokładnie ta pułapka

```
Authentication-Results: spf=pass (sender IP is 140.205.208.121)
 smtp.mailfrom=e.seguro-autoo.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none
 header.from=e.seguro-autoo.com;compauth=pass reason=100
```

Rozbicie:
- **`spf=pass`** — IP `140.205.208.121` jest autoryzowane do wysyłki w imieniu `e.seguro-autoo.com`. Oczywiście że jest — atakujący **sam skonfigurował** rekord SPF dla swojej domeny.
- **`dkim=none`** — wiadomość w ogóle nie została podpisana DKIM. Nie "fail", tylko brak podpisu — atakujący się tym nie przejął.
- **`dmarc=pass action=none`** — DMARC przechodzi (bo SPF jest zgodny/"aligned" z domeną z `From`), więc żadna akcja (np. odrzucenie) nie została podjęta.
- **`compauth=pass reason=100`** — to dodatkowy, **własny wynik Microsoftu** ("composite authentication") łączący SPF/DKIM/DMARC z dodatkową heurystyką — też Pass.

**Wniosek:** Wszystko przeszło uwierzytelnianie na "zielono" — a to nadal phishing. To najlepszy możliwy dowód na regułę z sekcji wyżej: SPF/DKIM/DMARC = Pass mówi tylko *"ta domena wysłała tę wiadomość zgodnie ze swoją własną konfiguracją"*, a nie *"ta domena jest bezpieczna"*.

---

## Podsumowanie

Message-ID mówi ci **kto go nadał**, a nie **kto wysłał maila**. Te dwie rzeczy nie zawsze są tym samym — szczególnie gdy odbiorca korzysta z usługi pocztowej, która nadpisuje ten nagłówek podczas odbierania wiadomości.

SPF/DKIM/DMARC mówią ci, czy nadawca był **autoryzowany dla swojej własnej domeny** — nie mówią ci, czy ta domena należy do kogoś godnego zaufania.

---

**Tags:** #phishing-analysis #email-headers #message-id #spf #dkim #dmarc
