# BugHunterPro 🎯

**Automated Bug Bounty Hunting Framework**

Un framework modular para automatizar reconocimiento, escaneo de vulnerabilidades y generación de reportes en bug bounty hunting.

## 🚀 Características

✅ Enumeración de Subdominios
✅ Escaneo de Puertos  
✅ Detección de Vulnerabilidades (SQLi, XSS, IDOR)
✅ Generación de Reportes (JSON + Markdown)
✅ Modos de Escaneo (Normal / Aggressive)

## 📋 Requisitos

- Python 3.8+
- nmap
- pip

## 🔧 Instalación

\\\ash
git clone https://github.com/RedamusOffSec05/bughunterpro.git
cd bughunterpro
pip install -r requirements.txt
\\\

## 💻 Uso

\\\ash
# Modo normal
python BugHunterPro.py --target example.com

# Modo agresivo
python BugHunterPro.py --target example.com --mode aggressive
\\\

## 📊 Reportes

Genera reportes automáticos en JSON y Markdown con:
- Lista de subdominios encontrados
- Vulnerabilidades detectadas
- Puntuaciones CVSS
- Recomendaciones

## 🛡️ Consideraciones Legales

⚠️ **IMPORTANTE:** Solo usar en targets autorizados

- Respetar términos de bug bounty programs
- Verificar scope antes de escanear
- Usar responsablemente

### Programas de Bug Bounty
- [HackerOne](https://www.hackerone.com)
- [Bugcrowd](https://www.bugcrowd.com)
- [Intigriti](https://www.intigriti.com)

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Fork, crea una rama y envía un Pull Request.

## 📄 Licencia

MIT License - Ver LICENSE para detalles

## 👤 Autor

**Steven (RedOffSec05)**
- Security Researcher
- Bug Bounty Hunter
- Cybersecurity Consultant

---

**Happy Hunting! 🎯**
