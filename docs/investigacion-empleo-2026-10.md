# Búsqueda de empleo remoto — Malware / RE / CTI / Detection (verificación al 7-oct-2026)

**Candidato:** Miguel Ángel Rodríguez Bohórquez · Bogotá, Colombia · github.com/Maracuya4263
**Metodología:** todo lo marcado como *verificado* se consultó hoy (7-oct-2026) directamente en el sistema de selección (ATS) de cada empresa (APIs públicas de Greenhouse, Lever, Ashby, BambooHR, Workday, Personio, Breezy) o en su página de carreras. Lo que no se pudo abrir se marca como **no verificado**. Para repetir la verificación: `python3 scripts/check_jobs.py`.

---

## 0. Resumen ejecutivo (lo que cambia respecto a tu investigación previa)

1. **Group-IB LATAM está cerrada.** El enlace de "Cyber Threat Intelligence Analyst – LATAM" (Greenhouse 4892479101) redirige con `error=true`, y `/careers/malware-analyst-latam` da 404. Hoy hay 34 vacantes en su Greenhouse y **ninguna en LATAM técnica** (solo 2 de fraude en Brasil). Ya no es prioridad 1 para postular, aunque sí para vigilarla.
2. **La mejor oferta abierta para ti es Wazuh — "Detection Engineer (Threat Research)"**, 100 % remota y orientada a *early-career*: Sysmon, MITRE ATT&CK, reglas de detección, Python/Git. Encaja casi punto por punto con tu laboratorio.
3. **Intel 471 tiene abierta "Cyber Threat Researcher (Europe or LATAM, Remote)"** (publicada el 2-sep-2026, contrato **B2B**). Exige experiencia previa en foros del *underground* y vHUMINT, así que el encaje es medio-bajo. La de "Malware Analyst/Reverse Engineer LATAM" **ya no está publicada**.
4. **CrowdStrike no sirve desde Colombia ahora mismo.** "Analyst I, Falcon Complete" solo está en EE. UU., Reino Unido, Canadá y Japón, y "Security Researcher – Spanish/Portuguese Speaking" solo en EE. UU. (USD 70–95k).
5. **Fechas que ya pasaron o cerraron:**
   - CFP de **Black Alpaca**: cerró el **5-oct-2026** (el evento sigue el 14-nov y es gratis).
   - **Ekoparty**: es **hoy** (7–9 oct).
   - Examen gratuito **ISC2 CC** (One Million Certified): cerró inscripciones el 20-may-2026.
6. **Plan B pentesting: Fluid Attacks** (empresa colombiana). Contrata pentesters 100 % remotos, valora las habilidades por encima de los títulos, pide inglés B1 y CTFs.

### 0b. Ranking: opciones seguras (empresa legítima, postulación directa) y realistas para tu nivel

"Segura" significa aquí:
- La empresa es real y la oferta está en **su propio** portal de selección (no en agregadores ni agencias).
- La oferta acepta a alguien en Colombia o LATAM.
- **No pide 4+ años de experiencia ni certificaciones senior.**

Ordenadas por probabilidad realista, no por preferencia:

| # | Opción | Por qué es segura | Por qué es realista para ti | Riesgo principal |
|---|---|---|---|---|
| 1 | **Fluid Attacks — Pentester** (plan B) | Empresa colombiana conocida (clientes como Bancolombia); postulación en fluidattacks.com | Dice explícitamente que no le importan los títulos; pide inglés B1 y conocimientos básicos; remoto desde cualquier lugar | Proceso con pruebas técnicas y "certificación pre-empleo" (no pude leer los detalles) |
| 2 | **Wazuh — Detection Engineer (Threat Research)** | Empresa de software open source; oferta en wazuh.com | Pide perfil *early-career*, Sysmon y ATT&CK: es casi tu laboratorio | Pide 1–3 años de experiencia; no confirma que acepte Colombia |
| 3 | **Intel 471 — Talent Pool** (perfil malware/CTI) | Proveedor de CTI reconocido; postulación en su BambooHR; contrata en LATAM como B2B | Convocatoria abierta: tu research público (RedLine, PipeMagic) es tu carta | Sin plazo ni vacante concreta; puede no haber respuesta |
| 4 | Intel 471 — Cyber Threat Researcher (LATAM) | Igual que el anterior | Español requerido; el análisis de malware cuenta como ventaja | Exige experiencia en foros criminales y HUMINT que no tienes |
| 5 | Vigilar la reapertura: Group-IB LATAM, Intel 471 Malware Analyst LATAM | Las dos ya contrataron en LATAM antes | Encaje alto si reabren | Hoy están cerradas |

**Lo que descarté por inseguro o irreal** (detalle en la sección 1c): ofertas de "agregadores" que ya no existen en el portal real de la empresa; roles en Colombia que piden 6+ años (Accenture), certificaciones senior tipo CISSP (Hyland) o experiencia FedRAMP (GFT); y rebotes de intermediarios.

---

## 1. Tabla de ofertas y canales verificados

Leyenda de encaje: **Alto** = puedes postular ya con buenas opciones · **Medio** = postular, pero con brechas claras · **Bajo** = nivel o requisitos muy por encima, o ubicación dudosa.

### 1a. Ofertas concretas

| Empresa / canal | Rol | URL | Estado verificado (7-oct) | Encaje | Qué falta |
|---|---|---|---|---|---|
| **Wazuh** | Detection Engineer (Threat Research) | https://wazuh.com/job/senior-software-engineer-cti/ (la URL dice "senior software engineer cti" pero la página es este rol) | **Abierta.** Remote, full-time. Pide 1–3 años en SOC, detección, threat hunting o CTI; ATT&CK; Sysmon/auditd; reglas en algún formato (Wazuh, Sigma, EQL, SPL); Python y Git; inglés fluido. Bonus: Atomic Red Team o Caldera, análisis de scripts y contribuciones públicas (Sigma, blog, CTF). | **Alto** | 1) No dice explícitamente si acepta Colombia: confírmalo en la entrevista. 2) No tienes reglas de detección publicadas: crea 5–10 reglas Wazuh/Sigma a partir de tu lab de Sliver y RedLine antes de postular. 3) Experiencia: preséntala como laboratorio y research propio, sin inflarla. |
| **Intel 471** | Cyber Threat Researcher (Europe or LATAM, Remote) | https://intel471.bamboohr.com/careers/334 | **Abierta.** Publicada el 2-sep-2026. **B2B Contractor**. Español + inglés requeridos (cumples). Exige experiencia previa monitoreando el *underground*, OPSEC y personas (vHUMINT). Análisis de malware "es una ventaja". | **Medio-bajo** | Te falta experiencia en foros criminales y HUMINT. Tu argumento: malware intel (RedLine es un stealer del ecosistema eCrime). Postula sabiendo que es un tiro largo. |
| Intel 471 | Talent Pool (general) | https://intel471.bamboohr.com/careers/197 | **Abierta** (convocatoria permanente) | Medio | Úsala para el perfil de malware analyst, ya que la oferta específica de LATAM no está publicada. |
| Intel 471 | Lead Vulnerability Intelligence Analyst (Europe or LATAM) | https://intel471.bamboohr.com/careers/340 | Abierta (25-sep-2026), B2B | Bajo | Es rol de líder: pide nivel SME, PoCs y honeypots. |
| Intel 471 | Malware Analyst / Reverse Engineer (LATAM) | — | **No publicada** en su BambooHR hoy (solo aparece en agregadores antiguos) | — | Vigilar con el script. |
| **Group-IB** | Cyber Threat Intelligence Analyst – LATAM / Threat Intelligence & Malware Analyst | https://www.group-ib.com/careers/ | **Cerrada.** El enlace de Greenhouse redirige con error y la página de malware-analyst-latam da 404. Ninguna de las 34 vacantes actuales es técnica en LATAM. Prácticas: la página existe, pero no hay vacantes de prácticas publicadas. | (Alto si reabre) | Vigilar semanalmente. Si reabre, es la que mejor encaja con tu perfil (español, banca/RAT LATAM). |
| CrowdStrike | Analyst I, Falcon Complete | crowdstrike.wd5.myworkdayjobs.com (búsqueda "Falcon Complete") | Abierta solo en **EE. UU., Reino Unido, Canadá/PST y Japón**. 0 resultados para "Colombia". | Descartada | No contratan esto en Colombia. |
| CrowdStrike | Security Researcher – Spanish/Portuguese Speaking (Counter Adversary Ops, eCrime LATAM) | https://crowdstrike.wd5.myworkdayjobs.com/crowdstrikecareers/job/USA---Austin-TX/Security-Researcher---Spanish-Portuguese-Speaking_R30106 | Abierta, pero sus 52 ubicaciones son todas en EE. UU. (USD 70–95k). Cierra el 15-nov-2026. | Descartada | Exige residir en EE. UU. Dato útil: confirma que el perfil "CTI eCrime en español" tiene demanda. |
| Google / Mandiant | Senior Red Team Security Consultant (Colombia/México/Brasil) | google.com/about/careers (búsqueda "Mandiant", ubicación Colombia) | Abierta; es el **único** rol de Mandiant con Colombia | Bajo | Es senior. No hay roles de CTI o malware en español publicados hoy. |
| Recorded Future | — | job-boards.greenhouse.io/recordedfuture | 49 vacantes, **ninguna en LATAM** (Senior Malware Analyst en Gotemburgo; TI Response en Londres) | — | Entró a Colombia en jul-2026 (VP LATAM: Mauricio Palacios) y su equipo **Insikt** cubre LATAM. Por ahora es un objetivo de networking, no una postulación. |
| Huntress | — | job-boards.greenhouse.io/huntress | 35 vacantes: EE. UU., Australia, Irlanda y Reino Unido. Nada en LATAM. | Descartada | — |
| Red Canary | — | redcanary.com/job-openings → **redirige a Zscaler** | Ahora es parte de Zscaler. Sus roles de detección y threat research son solo en EE. UU. | Descartada | — |
| VMRay | — | vmray-gmbh.jobs.personio.de | 6 vacantes, ninguna de analista o detección (antes eran "Remote Europe") | — | Vigilar; históricamente solo Europa. |
| ANY.RUN | — | any.run/careers → 404 | **No verificable** | — | Sin página de carreras pública. |
| ESET Latinoamérica | — | eset.com/latam/.../trabaja-con-nosotros → 404 | **No verificable** | — | Su laboratorio LATAM está en Buenos Aires. Contacto vía WeLiveSecurity / LinkedIn de sus investigadores. |
| Kaspersky (GReAT) | Security Researcher (GReAT) | careers.kaspersky.com/vacancy/668bbf4ab63848f9dd858476 | Abierta, pero en **Moscú**. En LATAM solo hay preventa en Bogotá. | Descartada | — |
| SentinelOne / Sophos / Elastic | Varios roles de TI y Threat Analyst | (sus ATS) | Abiertos solo en Europa, Canadá, India o EE. UU.; nada en LATAM | Descartada | — |
| Expel | Associate SOC Analyst (Remote) | https://expel.com/about/career-listing/8588028002 | Abierta, pero **solo con autorización de trabajo en EE. UU.** (USD 85–90k) | Descartada | — |
| Bishop Fox | Penetration Tester (Mexico, Remote) | bishopfox.com/jobs?gh_jid=7905132 | Abierta; exige **autorización de trabajo en México** y 4+ años | Descartada | — |
| Canonical | Threat Intelligence Lead (Home based – Worldwide) | https://job-boards.greenhouse.io/canonical/jobs/5144666 | Abierta (desde 2024). Remota mundial. | Bajo | Es de liderazgo. Sirve como referencia de que Canonical contrata seguridad en todo el mundo. |
| Clara (fintech LATAM) | Security Engineer — Bogotá/CDMX | https://job-boards.greenhouse.io/clara/jobs/5236289007 | Abierta (11-sep-2026). Pide 2–4 años en seguridad cloud (AWS/GCP), AppSec, Splunk y EDR. **Modalidad no indicada**. El rol *Early Career* es solo en CDMX híbrido. | Medio-bajo | No consta que sea 100 % remoto. Te falta seguridad cloud. Sí encaja la parte de Splunk/EDR y la investigación de incidentes. |
| **Fluid Attacks** (plan B) | Pentester | https://fluidattacks.com/careers/ | **Abierta (convocatoria general).** "You can be anywhere on Earth". "Damos poca importancia a los estudios formales". Piden conocimientos básicos de desarrollo y ciberseguridad, **inglés B1** y, idealmente, CTFs. | **Alto (plan B)** | El FAQ menciona un "proceso de certificación pre-empleo" y pruebas técnicas, pero sus respuestas cargan de forma dinámica y no pude leerlas. Revisa https://fluidattacks.com/careers/faq/ antes de postular. |
| Axur (Infoblox) | Cyber Threat Intelligence Researcher | apply.workable.com/axur | **0 vacantes** en su Workable hoy. La oferta "worldwide" de los agregadores ya no está. | — | Vigilar. |
| Flashpoint / ZeroFox / Binarly / SOCRadar | — | Ashby / Rippling / Breezy | Sin roles de analista abiertos (Flashpoint: 4 vacantes; ZeroFox: 4; Binarly: "no open roles"; SOCRadar: solo ventas) | — | Los agregadores mostraban ofertas de 2025 ya cerradas. |
| ReversingLabs, Control Risks | — | apply.workable.com | **No verificable**: Workable bloqueó por límite de peticiones (IP compartida) | ? | Revísalo tú desde tu navegador. |
| Grupo Mariposa (vía Get on Board) | Especialista de Seguridad Informática | https://www.getonbrd.com/jobs/especialista-de-seguridad-informatica-grupo-mariposa-remote | Abierta (28-sep-2026), *fully remote*, USD 2.000–3.000 | Medio-bajo | Es un rol generalista de seguridad TI, no malware ni CTI. Confirma qué países acepta. |

### 1b. Canales, comunidades, eventos y programas

| Canal | Tipo | URL | Estado verificado | Encaje | Qué hacer / qué falta |
|---|---|---|---|---|---|
| Hacker News "Who is hiring?" (oct-2026) | Hilo mensual | https://news.ycombinator.com/item?id=49922569 | Publicado el 1-oct. Filtré sus 233 ofertas: **ninguna de seguridad remota que acepte LATAM**. | Bajo | Rendimiento muy bajo para tu nicho. |
| HN "Who wants to be hired?" (oct-2026) | Hilo mensual | https://news.ycombinator.com/item?id=49922568 | Publicado el 1-oct (598 comentarios) | Medio | Publicar tu perfil (**requiere tu OK**). El próximo hilo será hacia el 2-nov. |
| r/netsec Hiring Thread (trimestral) | Hilo | reddit.com/r/netsec | El de Q3-2026 se publicó el 2-jul-2026. **No pude confirmar el de Q4.** | Medio | Revisar a inicios de octubre. Exige que se declaren requisitos de ciudadanía, así que es fácil filtrar. |
| r/ReverseEngineering Hiring Thread (3 veces al año) | Hilo | reddit.com/r/ReverseEngineering | Existe (reglas: declarar ciudadanía, clearance, remoto). **No verifiqué la edición 2026.** | Medio | Revisar en ene, may y sep. |
| infosec-jobs.com | Board de infosec | https://infosec-jobs.com | Activo (13k ofertas en 60 días), pero mayoritariamente EE. UU., Europa e India | Bajo | Úsalo solo con el filtro de país o remoto. |
| Get on Board — categoría Ciberseguridad | Board tech LATAM | https://www.getonbrd.com/jobs/cybersecurity | Activo, con 22 ofertas, casi todas en Chile y con salarios en USD | Bajo-medio | Útil como referencia salarial LATAM. |
| **Ekoparty 2026** | Conferencia | https://ekoparty.org | **7–9 oct 2026 (hoy)**, CEC Buenos Aires. Hay Hackademy (formación) y han existido becas. | Medio | No llegas en persona. Sigue charlas y CTF, y anota a quién contactar. Postula a las becas de Hackademy en la edición 2027. |
| **Black Alpaca 2026** | Conferencia (Lima) | https://sessionize.com/black-alpaca-2026 | **CFP CERRADO el 5-oct-2026.** Evento el 14-nov, gratuito; no cubren viajes. | Medio | Ya no puedes enviar charla. Asiste o síguelo si puedes. |
| DragonJARCON | Conferencia (Colombia) | https://luma.com/dragonjarcon | La edición 2026 ya fue (10–11 sep, Medellín). El CFP 2026 cerró el 31-mar. | Alto (local) | Prepara una charla para el CFP 2027 (≈ marzo). Por ejemplo: "PipeMagic: protocolo C2 y detección". |
| BSides Colombia | Conferencia | https://sessionize.com/bsides-colombia-2026 | La edición 2026 ya fue (24–25 abr, Pereira). | Alto (local) | Apunta al CFP 2027. |
| OALabs Discord | Comunidad RE/malware | discord.com/servers/oalabs-885624530071085097 | Activo (~5,8k miembros), abierto a todos los niveles | Alto | Unirse y compartir tus análisis (**requiere tu OK** para publicar). |
| MalwareTech Discord | Comunidad | discord.com/servers/malwaretech-448237321708503041 | Existe | Medio | — |
| abuse.ch (MalwareBazaar / ThreatFox / Community Hub) | Contribución CTI | https://abuse.ch · https://bazaar.abuse.ch | Activo. **Community Hub** lanzado en jul-2026 para reconocer a contribuyentes. Piden "solo malware confirmado". | Alto | Crear cuenta y subir IOCs y YARA de RedLine y PipeMagic (**requiere tu OK**). |
| capa-rules (Mandiant / Google) | Contribución RE | https://github.com/mandiant/capa-rules | Activo (~2k commits). Tiene **nursery** para reglas sin pulir, con lógica sólida y metadatos incompletos. | Alto | Un PR al nursery con una capacidad de PipeMagic. |
| SigmaHQ | Contribución detección | https://github.com/SigmaHQ/sigma | Activo. Exige pasar `test_logsource.py`, `test_rules.py` y la validación de sigma-cli. | Alto | Un PR con una regla basada en tu lab de Sliver. Es ideal para la postulación a Wazuh. |
| SOC Prime Threat Bounty | Bounty de reglas Sigma | https://my.socprime.com/tdm-developers/ | El programa existe (600+ investigadores). **No verifiqué pagos ni condiciones de 2026.** | Medio | Es opcional; prioriza antes SigmaHQ (público y citable). |
| Recorded Future Insikt (LATAM) | Networking | — | Tienen un equipo de analistas para LATAM. RF entró a Colombia en jul-2026. | Medio | Seguir a sus analistas y leer sus reportes LATAM. Contactar solo con algo que aportar. |
| Detection Engineering Weekly | Newsletter | https://detectionengineering.net | Activo (Zack Allen, Datadog). **No confirmé que tenga sección de empleos.** | Medio | Suscribirse por el contenido. |
| ISC2 Certified in Cybersecurity gratis | Certificación | isc2.org | **Cerrado**: sin inscripciones nuevas desde el 20-may-2026 | — | Ya no aplica. |
| Becas OEA–VIU (maestrías virtuales, 60 %) | Beca | — | Convocatoria 2026 **cerrada** (11-may a 30-jun) | Bajo | Revisar la convocatoria 2027 si te interesa una maestría. |

### 1c. Búsqueda ampliada: CTI, pentesting, SOC y Colombia (7-oct-2026)

Revisé, además, consultoras con sede en Colombia, firmas ofensivas LATAM, plataformas de bug bounty y fintechs. Todo se consultó en el ATS de cada empresa salvo donde se indica.

| Empresa | Rol encontrado | Estado / fuente | Veredicto |
|---|---|---|---|
| Accenture (Bogotá) | Security Managed Services Specialist (Check Point) | Workday, publicada el 15-sep, "Remote" | **No encaja**: pide 6+ años con firewalls Check Point |
| Kyndryl (Bogotá) | Cyber Resiliency Specialist | Workday, 6-oct, parcialmente remota | No encaja: es de backup y continuidad, no de amenazas |
| PwC, Citi, Visa, Trend Micro, Proofpoint, Mastercard | — | Workday: 0 roles de SOC, CTI o pentest en Colombia (solo ventas, IAM u operaciones) | Nada |
| Hyland | Cyber Security Analyst – SOC (Colombia, remoto) | Vista en Remote Rocketship. **No pude abrir su portal** (iCIMS embebido). | Encaje bajo: pide "significant experience" y CISSP, GIAC o Security+ |
| GFT | Security Specialist (Colombia, remoto) | Vista en Remote Rocketship | No encaja: cumplimiento FedRAMP/IL4 en GCP |
| Stefanini LATAM | Analista DLP para SURA Colombia / Cyber Security Analyst (Colombia, remoto) | Vista en un agregador; **no pude verificarla** en su portal | Medio-bajo. Además, Stefanini es *outsourcing* de TI (te asignan a un cliente), cerca de lo que querías evitar |
| Faraday (Argentina) | Security Consultant | Zoho Recruit: **Buenos Aires, no remoto** | Descartada |
| Onapsis (Argentina/EE. UU.) | — | Greenhouse: 5 vacantes, ninguna de seguridad en LATAM | Nada |
| Bitso, Belvo, Addi, Cobre, dLocal, Yuno | — | Sin roles de seguridad ofensiva o CTI abiertos a Colombia remoto (solo fraude y cumplimiento) | Nada |
| Bugcrowd | AppSec Engineer (Remote **Brazil**), Product Security (Costa Rica) | Greenhouse | Fuera de Colombia y con nivel más alto |
| HackerOne | Triage Intake Analyst (India), Lead Triage (EE. UU.) | Ashby / búsqueda | Nada en LATAM |
| Intigriti, YesWeHack | — | Sin portal accesible, o en Welcome to the Jungle (Francia) | No verificable |
| Appgate, ReversingLabs, Control Risks | — | Workable bloqueado por límite de peticiones | **No verificable**. Revísalos tú en el navegador |

**Conclusión honesta:** en el mercado remoto desde Colombia casi no hay vacantes de SOC, CTI o pentest para perfiles sin experiencia laboral. Las que aparecen como "Colombia remoto" en agregadores son mayoritariamente de nivel medio o senior, o de cumplimiento. Tus mejores cartas son las opciones del ranking 0b, más construir evidencia pública (sección 3), que es lo que compensa la falta de experiencia formal.

---

## 2. Contratación remota desde Colombia

### 2a. Lo verificado

- **Modalidad real de las ofertas que aceptan LATAM:** las dos de Intel 471 se publican como **"B2B Contractor"**, es decir, facturas tú como independiente. El resto de las ofertas no lo especifica.
- **Salario mínimo 2026 (SMMLV):** COP 1.750.905, más auxilio de transporte de COP 249.095 (Decretos 1469 y 1470 de 2025).
- **TRM:** COP 3.312,84 / USD (1-oct-2026) y 3.307,73 (2-oct-2026).
- **Si eres contratista independiente (prestación de servicios):**
  - Cotizas sobre un IBC del **40 % del ingreso mensual** (mínimo 1 SMMLV, máximo 25).
  - **Salud 12,5 %**, **pensión 16 %** y **ARL** según el riesgo (0,522 %–6,96 %). Riesgo I es 0,522 %.
  - Existe un nuevo tipo de cotizante "15 – Contratista" (Res. 000467 de 2025).
- **IVA por exportación de servicios:** un servicio prestado desde Colombia y usado exclusivamente en el exterior por una empresa sin negocios en el país está exento de IVA. Requisitos: inscribirte como exportador de servicios en el RUT y conservar la factura y el contrato u oferta aceptada.
- **Si te contratan por EOR (Deel, Remote, etc.):** eres empleado bajo ley colombiana y recibes:
  - **Prima de servicios** (1 salario al año, en junio y diciembre).
  - **Cesantías** (1 salario al año, consignadas al fondo antes del 14-feb).
  - **Intereses del 12 %** sobre las cesantías.
  - Seguridad social y retención en la fuente.
  - En total, las prestaciones suman ~22 % sobre el salario.
- **Referencias salariales publicadas (todas exigen EE. UU., solo sirven como techo de mercado):**
  - Expel, Associate SOC Analyst: USD 85–90k/año.
  - CrowdStrike, Security Researcher en español: USD 70–95k/año.
- **Referencia LATAM publicada:** Get on Board, rol remoto de seguridad TI de nivel medio, **USD 2.000–3.000/mes**.

### 2b. Lo estimado (no verificable con una fuente oficial)

| Escenario | Rango mensual estimado (bruto) | Base |
|---|---|---|
| Empresa colombiana, junior SOC/ciberseguridad | COP 3–6 M ≈ **USD 900–1.800** | Guías salariales 2026 (Jobrise, KeepCoding) y ofertas en Elempleo con COP 2,5–3 M para 1 año de experiencia. Fuentes comerciales, no oficiales. |
| Empresa extranjera, junior, contratista LATAM | **USD 1.500–2.500** | Ofertas remotas junior en Perú (USD 1.200–1.800) y datos de una agencia de staffing (HireInSouth: junior SOC LATAM USD 30–42k/año). Fuentes sesgadas: tómalo como orden de magnitud. |
| Empresa extranjera, CTI / detección con algo de experiencia | **USD 2.500–4.000** | Rango Get on Board para nivel medio, más el margen de empresas de EE. UU. y Europa. |

**Tu meta de USD 2.000–3.000/mes es realista** para un primer rol remoto con empresa extranjera, sobre todo como contratista. Por debajo de USD ~1.500 casi no compensa frente a un empleo local.

**Cómo comparar contratista frente a EOR (estimación propia, antes de impuesto de renta):**
- Como contratista con USD 2.500/mes (≈ COP 8,27 M):
  - Seguridad social ≈ COP 0,96 M/mes (≈ USD 290, ~11,6 %), sobre un IBC de COP 3,31 M.
  - Sin prima, sin cesantías y **sin vacaciones pagadas**.
- Como empleado vía EOR:
  - Te descuentan ~8 % (salud + pensión).
  - Recibes además ~18 % en prestaciones y 15 días hábiles de vacaciones pagadas.
- **Regla práctica: una tarifa de contratista debe ser ~25–35 % más alta que un salario EOR para equivaler.** Ejemplo: USD 2.600–2.700 como contratista ≈ USD 2.000 de salario EOR.
- **Pendiente de validar con un contador:**
  - Impuesto de renta (régimen ordinario frente a SIMPLE).
  - Retenciones.
  - La canalización de divisas (Wise, Payoneer, cuenta en USD) y su declaración de cambio.

---

## 3. Plan de 30 días (8-oct → 6-nov-2026)

Nada de esto se envía ni se publica en tu nombre sin tu confirmación. Los pasos marcados con 🔒 requieren tu OK.

### Semana 1 (8–14 oct): postular a lo que está abierto, con evidencia
- **Wazuh (prioridad 1):**
  - Monta Wazuh en tu lab (agente en la VM Windows 10 del ejercicio de Sliver).
  - Escribe 5 reglas y decoders que detecten lo que ya documentaste: inyección/hollowing de RedLine, carga reflectiva y syscalls indirectos del loader de Sliver, persistencia. Mapea cada una a ATT&CK y documenta qué la evadiría (es literalmente lo que pide la oferta).
  - Publica todo en un repo nuevo `detections` 🔒.
  - Postula entre el 12 y el 14-oct 🔒.
- **Fluid Attacks (plan B):** lee el FAQ en el navegador, haz algún reto de su CTF y postula como Pentester 🔒.
- **Intel 471:** postula al **Talent Pool** con el perfil de malware analyst. La oferta Cyber Threat Researcher es opcional, sabiendo que te falta experiencia HUMINT 🔒.
- **GitHub:**
  - Crea el README de perfil (hoy no tienes) con 3 líneas: malware RE, memory forensics, detection.
  - Fija tus 2 repos y el nuevo `detections`.
  - Añade un resumen ejecutivo en inglés al README de `malware-memory-forensics`.
- **Ekoparty (7–9 oct):** sigue las charlas de malware y CTI y anota 3–5 ponentes con quienes conectar.
- **Inglés:** escribe en inglés la descripción de cada regla (un párrafo explicando qué detecta y sus límites; la oferta de Wazuh lo pide literalmente).

### Semana 2 (15–21 oct): contribuciones públicas que se puedan citar
- **SigmaHQ:** prepara 1 PR con una regla derivada de tu lab, pasando `test_rules.py` y `test_logsource.py` 🔒.
- **capa-rules:** prepara 1 PR al *nursery* con una capacidad observada en PipeMagic (por ejemplo, el framing de C2 o la librería TLS embebida) 🔒.
- **abuse.ch:** crea cuenta y sube tus YARA e IOCs de RedLine y PipeMagic a MalwareBazaar y ThreatFox 🔒. Revisa antes que no incluyan datos de tu lab.
- **Blog en inglés (1 post):** "From RedLine memory forensics to detections". Puede ser GitHub Pages o similar 🔒.
- **Networking:** únete a OALabs Discord; preséntate con un enlace a tu análisis de PipeMagic 🔒.
- **Inglés:** 3 sesiones de 20 min explicando en voz alta un análisis tuyo. Grábalas y escúchate (vocabulario: *unpacking, hollowing, beaconing, false positive*).

### Semana 3 (22–28 oct): profundidad y re-verificación
- **Atomic Red Team / Caldera en tu lab:**
  - Emula 5 técnicas (T1055, T1620, T1106, T1547, T1071).
  - Valida tus reglas Wazuh y Sigma contra ellas y documenta FP/FN (bonus explícito de la oferta de Wazuh).
- Corre `python3 scripts/check_jobs.py` el lunes y el jueves. Si Group-IB reabre LATAM, postula en 48 h 🔒.
- Revisa los hilos de contratación de r/netsec (Q4) y r/ReverseEngineering.
- **Inglés:** simula una entrevista técnica de 30 min. Puedo hacer de entrevistador de Wazuh o Intel 471 si quieres.

### Semana 4 (29 oct–6 nov): visibilidad y seguimiento
- **HN "Who wants to be hired?" (nov-2026, ~2-nov):** publica tu perfil (Bogotá, remoto, malware/CTI/detection, enlaces) 🔒.
- **Seguimiento:** responde a las entrevistas y, si no hay respuesta en ~10 días hábiles, envía un mensaje breve 🔒.
- **CFP 2027:** esboza el abstract de "PipeMagic: protocolo C2, autenticación post-handshake y detección" para DragonJARCON y BSides Colombia 2027.
- **Black Alpaca (14-nov):** el CFP está cerrado; decide si asistes o lo sigues en línea.
- **Métricas al cierre:**
  - ≥4 postulaciones de calidad (Wazuh, Fluid Attacks, Intel 471 y 1 más).
  - ≥2 PRs públicos (Sigma, capa).
  - 1 post en inglés.
  - 1 repo `detections`.

---

## 4. Pendientes y límites de esta verificación

- **No verificado:**
  - ReversingLabs y Control Risks (Workable bloqueó por límite de peticiones).
  - ANY.RUN y ESET LATAM (sin página de carreras accesible).
  - Respuestas del FAQ de Fluid Attacks (contenido dinámico).
  - Pagos 2026 de SOC Prime.
  - Hilos Q4 de r/netsec y r/ReverseEngineering.
- **Wazuh:** la oferta dice "Remote" sin listar países. Wazuh opera de forma distribuida, pero **no pude confirmar que acepte Colombia**. Pregúntalo en el primer contacto.
- **Encaje:** en las ofertas que piden 1–3 años de experiencia, tu evidencia es de laboratorio y research propio. Preséntala así, con enlaces; no la presentes como experiencia laboral.
- Las cifras de la sección 2b son estimaciones, no datos oficiales.

## 4b. Seguridad: cómo no caer en ofertas falsas (importante en tu sector)

- **Las estafas de empleo dirigidas a perfiles técnicos son reales y activas.** La campaña norcoreana "Contagious Interview" (WaterPlum) usa entrevistas técnicas falsas para que la víctima clone y ejecute un repositorio malicioso. Según un aviso conjunto citado por CSA, infectó más de 30.000 equipos entre dic-2025 y jul-2026; Microsoft publicó sobre ella en mar-2026. Tu perfil (malware/RE) también es objetivo.
- **Reglas prácticas:**
  1. Postula **solo desde el portal oficial** de la empresa (dominio propio o su ATS: greenhouse.io, lever.co, bamboohr.com, myworkdayjobs.com, ashbyhq.com, workable.com). Llega a él desde la web oficial de la empresa, no desde un enlace que te envíen.
  2. Comprueba que el reclutador escriba desde un **correo del dominio de la empresa**. Desconfía de Telegram, WhatsApp, Gmail o Outlook personales.
  3. **Nunca pagues** por capacitación, equipos, "verificación de antecedentes" o certificaciones como requisito para entrar.
  4. **Ejecuta cualquier "prueba técnica" que traiga código o binarios solo en una VM aislada**, como haces con malware. Nunca en tu equipo personal, y sin npm, pip ni scripts sin revisar.
  5. No des cédula, datos bancarios ni contraseñas antes de tener un contrato firmado con una entidad verificable.
  6. Desconfía de ofertas sin entrevista, con pago desproporcionado o de "tareas" pagadas en cripto.
  7. Las agencias de staffing (por ejemplo, Vintti) quedan fuera por tu regla. Los agregadores como Remote Rocketship sirven solo para encontrar pistas: verifica siempre en el portal real.

## 5. Fuentes principales

- Group-IB Greenhouse API: https://boards-api.greenhouse.io/v1/boards/groupib/jobs · https://www.group-ib.com/careers/ · https://www.group-ib.com/careers/internship/
- Intel 471 BambooHR: https://intel471.bamboohr.com/careers/334 · /340 · /197
- Wazuh: https://wazuh.com/careers/ · https://wazuh.com/job/senior-software-engineer-cti/
- CrowdStrike Workday: https://crowdstrike.wd5.myworkdayjobs.com/crowdstrikecareers
- Google Careers (Mandiant): https://www.google.com/about/careers/applications/jobs/results/?q=Mandiant&location=Colombia
- Recorded Future: https://job-boards.greenhouse.io/recordedfuture · https://www.asuntoslegales.com.co/actualidad/recorded-future-ingresa-se-expande-al-mercado-de-ciberseguridad-colombiano-4438321 · https://impactotic.co/tecnologia/recorded-future-llega-a-colombia-ante-repunte-historico-de-ciberataques/
- Clara: https://job-boards.greenhouse.io/clara/jobs/5236289007
- Fluid Attacks: https://fluidattacks.com/careers/ · https://fluidattacks.com/careers/faq/
- Expel: https://expel.com/about/career-listing/8588028002 · Bishop Fox: http://www.bishopfox.com/jobs?gh_jid=7905132 · Canonical: https://job-boards.greenhouse.io/canonical/jobs/5144666
- Get on Board API: https://www.getonbrd.com/api/v0/categories/cybersecurity/jobs
- HN: https://news.ycombinator.com/item?id=49922569 · https://news.ycombinator.com/item?id=49922568
- Black Alpaca: https://sessionize.com/black-alpaca-2026 · Ekoparty: https://ekoparty.org · DragonJARCON: https://luma.com/dragonjarcon · BSides Colombia: https://sessionize.com/bsides-colombia-2026
- abuse.ch: https://abuse.ch/blog/introducing-abuse-ch-community-hub/ · capa-rules: https://github.com/mandiant/capa-rules · Sigma: https://github.com/SigmaHQ/sigma/blob/master/CONTRIBUTING.md
- ISC2: https://www.isc2.org/insights/2026/04/one-million-certified-cyber-conclusion
- SMMLV 2026: https://consultorsalud.com/aumento-del-salario-minimo-en-colombia-2026/ · TRM: https://www.dolar-colombia.com/2026-10-01
- Independientes: https://www.portafolio.co/economia/finanzas/seguridad-social-en-colombia-asi-deben-cotizar-dependientes-e-independientes-en-489097 · https://ugpp.gov.co/sites/default/files/Parafiscales/ABC-Independientes-Inexactos.pdf
- Exportación de servicios: https://www.gerencie.com/exencion-del-iva-en-la-exportacion-de-servicios.html
- EOR / prestaciones: https://topsourceworldwide.com/insights/hiring-in-colombia-prestaciones-sociales-contract-types/ · https://www.deel.com/blog/employer-of-record-colombia/
- Salarios (estimados): https://jobrise.io/es/blog/salario-cybersecurity-analyst-bogota-2026/ · https://www.hireinsouth.com/post/soc-analyst-salary
- Búsqueda ampliada: https://accenture.wd103.myworkdayjobs.com/AccentureCareers/job/Bogota-Carrera-7/Security-Managed-Services-Specialist_14737774 · https://kyndryl.wd5.myworkdayjobs.com/KyndrylProfessionalCareers/job/Bogota-Cundinamarca-Colombia/Cyber-Resiliency-Specialist_R-69617-1 · https://www.remoterocketship.com/publicjobs/company/hyland/jobs/cyber-security-analyst-soc-colombia-remote/ · https://www.remoterocketship.com/publicjobs/company/gft-technologies/jobs/security-specialist-colombia-remote/ · https://faradaysec.zohorecruit.com/jobs/Careers · https://jobs.ashbyhq.com/hackerone/8d1587f1-72de-49be-8867-8056a87014b3
- Estafas de empleo: https://microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews · https://labs.cloudsecurityalliance.org/research/csa-research-note-contagious-interview-waterplum-campaign-20/ · https://www.wknofm.org/show/protecting-your-money/2026-07-14/ftc-warns-job-scams-are-on-the-rise
