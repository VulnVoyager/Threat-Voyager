# Threat Voyager

**Threat Voyager** — это модульный, MITRE ATT&CK-ориентированный детектор угроз, написанный на Python, который анализирует **Windows Security** и **Sysmon** журналы для выявления фаз компрометации: от начального доступа до экcфильтрации данных.

Подходит для:
- SOC-аналитиков (1–2 линия)
- Threat hunters
- Красных/фиолетовых команд
- Аудиторов безопасности без EDR

---

## Возможности

✅ Обнаружение по MITRE ATT&CK (T1566.001, T1566.003, T1204, T1059.001, T1218, T1547.001, T1053.005, T1543.003, T1098, T1078, T1027, T1036, T1003.001, T1087, T1016, T1057, T1560, T1555, T1567, T1566.001 + T1204)  
✅ Автоматическая группировка событий в сессии по `LogonId`  
✅ Анализ живых журналов или `.evtx`-архивов  
✅ Распознавание:
- LOLBin-аудита (`rundll32`, `regsvr32`, `mshta`, `certutil`…)
- Обфускации PowerShell (`-EncodedCommand`, `IEX`)
- Подозрительных двойных расширений (`.pdf.exe`)
- Запуска с внешних носителей или из `%TEMP%`
- Работы с чувствительными файлами (куки, кошельки, история браузеров)
- Экзфильтрации на `discord.com`, `mega.nz`, `api.telegram.org`
- Создания пользователей, сброса паролей, добавления в админы  
✅ Построение дерева процессов (Office → PowerShell = тревога)  
✅ Генерация отчётов: список алертов или сессии с оценкой риска  
✅ Экспорт результатов в JSON

---

## Требования

- **ОС**: Windows (для Sysmon и Security-журналов)
- **Python**: 3.7+
- **PowerShell**: 5.1+ (встроен в Windows)
- **Sysmon**: должен быть установлен и настроен (рекомендуется [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config))

---

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/VulnVoyager/threat-voyager.git
   cd threat-voyager
2. (Опционально) Создайте файлы:
  known_ips.txt — список «белых» IP-префиксов
  sensitive_paths.json — пути к чувствительным данным

  Пример sensitive_paths.json:
  ```json
  {
  "corporate": ["\\.ssh\\", "\\AppData\\Roaming\\aws\\"],
  "financial": ["\\AppData\\Roaming\\Bitcoin\\wallet.dat"]
  }
  ```
---

## Использование
Анализ последних 6 часов (live):
``` python threat_voyager.py --hours 6 --verbose ```

Анализ архивных .evtx-файлов:
``` python threat_voyager.py ^
  --security C:\logs\Security.evtx ^
  --journal C:\logs\Sysmon.evtx ^
  --hours 24 ^
  --output alerts.json
```

Поддерживает группировку событий по LogonId и оценку риска сессий (режим --session-report)

Полный список опций:
``` python threat_voyager.py --help ```
