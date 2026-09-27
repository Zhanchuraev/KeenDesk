# Похожие решения

Поиск и просмотр первоисточников выполнены **28 сентября 2026**. Идея размещать RustDesk Server на роутере уже реализовывалась. Ниже — найденные близкие варианты; это не полный каталог и не утверждение об отсутствии других проектов.

| Решение | Платформа и назначение | Отличие от KeenDesk |
|---|---|---|
| [«RustDesk Server на ARM Cortex-A53» — Keenetic Community](https://forum.keenetic.ru/topic/27104-rustdesk-server-на-arm-cortex-a53/) | Автор SVBSPb описывает установку на KeeneticOS 5, прикладывает `S99rustdesk`, предлагает автоматический установщик и команды `status/start/stop/restart/doctor`. | Один из самых близких вариантов: сервер прямо на ARM64 Keenetic и автоматизация установки/запуска. В теме также обсуждаются установка пакета Entware и проблемы автозапуска. В рамках этого обзора чужой установщик не запускался, его совместимость с XKeen не проверялась. |
| [Пакет `rustdesk-server` в Entware](https://github.com/Entware/entware-rust/tree/master/rustdesk-server) | В просмотренном рецепте версия `1.1.15-1`; устанавливаются `hbbs`, `hbbr`, `rustdesk-utils` в `/opt/usr/bin`. Такая версия также присутствовала в списке пакетов проверенного ARM64-роутера. | Это готовые серверные бинарники. Просмотренный рецепт не устанавливает настройку доступа KeenDesk, его supervisor, NDM-hook или исключения XKeen. Наличие пакета и архитектуру нужно проверять в своём feed Entware. |
| [«RustDesk server на роутере» — форум Keenetic](https://forum.keenetic.ru/topic/25099-rustdesk-server-на-роутере/) | Автор vasek00 2 ноября 2025 описал ручной запуск официального ARM64-сервера на KeeneticOS 5.0.x и проверку клиентами Windows/смартфон. | Это непосредственно близкий пример для Keenetic. Описанный сценарий — ручное размещение и запуск бинарников, а не установщик KeenDesk с его правилами доступа и контролем служб. |
| [RouterDesk](https://github.com/medking82/RouterDesk) | Установщик RustDesk для **ASUSWRT-Merlin + Entware**, управление CLI/TUI, страница в интерфейсе роутера, обновления и watchdog. Автор указывает испытание на ASUS RT-BE92U. | Близок по идее автоматизации, но интегрирован с Merlin/JFFS и его hooks. Совместимость его установщика с Keenetic/Netcraze не заявлена; запускать его на Keenetic как готовую замену нельзя. |
| [Koolcenter_rustdesk](https://github.com/everstu/Koolcenter_rustdesk) | Плагин RustDesk Server для прошивок на основе ASUSWRT в экосистеме Koolcenter/Koolshare/Merlin. В README перечислены поддерживаемые ARMv8/ARMv7-модели. | Сервер на роутере с интеграцией в другую платформу. Это не пакет для KeeneticOS. |
| [OpenWrt `luci-app-rustdesk-server`](https://git.cdn.openwrt.org/project/luci/tree/applications/luci-app-rustdesk-server) | LuCI-интерфейс управления `hbbs`/`hbbr`: запуск, автозагрузка, ключ, журналы, параметры сервера. [Документация](https://git.cdn.openwrt.org/project/luci/plain/applications/luci-app-rustdesk-server/README.md). | Похож по назначению и имеет веб-интерфейс; использует OpenWrt UCI/procd/LuCI вместо Entware и NDM KeeneticOS. |
| [techahold/rustdeskinstall](https://github.com/techahold/rustdeskinstall) | Установщик сервера для Debian/CentOS-подобных систем с systemd, отдельные скрипты обновления и удаления. | Аналог автоматизации для обычного Linux/VPS. Не предназначен для прямого запуска в Entware Keenetic. |
| [Официальный rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) | Исходники и выпуски самого `hbbs`/`hbbr`. | Основа KeenDesk и других обвязок, а не самостоятельный аналог установщика для Keenetic. |

Дополнительные ссылки к этим решениям:

- [Скрипт `install_rd.sh` из темы SVBSPb](https://57974.ru/kee/install_rd.sh). Это адрес, опубликованный автором темы; содержимое по нему не удалось получить через использованный веб-инструмент, аудит и запуск не выполнялись.
- [Представление RouterDesk его автором в сообществе RustDesk](https://github.com/rustdesk/rustdesk/discussions/15636).
- [GitHub-каталог LuCI-приложения](https://github.com/openwrt/luci/tree/master/applications/luci-app-rustdesk-server); наличие и назначение сверены по официальному зеркалу OpenWrt и [Makefile](https://raw.githubusercontent.com/openwrt/luci/master/applications/luci-app-rustdesk-server/Makefile).
- [Объявление Entware от 23 февраля 2024 о добавлении rustdesk-server](https://entware.net/2024/02/23/Changelog.html).

KeenDesk использует официальный RustDesk Server OSS 1.1.16 и собственную обвязку для ARM64 Entware на Keenetic: ограничение входа по VPN-интерфейсам/подсетям, отдельный UID, известная схема обхода XKeen, восстановление правил после событий NDM и русский сценарий установки. Его фактические испытания и ограничения перечислены в [TESTING.md](../TESTING.md).

Отдельный готовый проект именно для Netcraze с тем же набором функций в проведённом поиске не найден. Это ограниченный результат поиска, не гарантия уникальности. Поддержку конкретной модели Netcraze нельзя вывести только из сходства платформ: требуется проверка архитектуры, Entware, netfilter и загрузочных hooks. Живое испытание KeenDesk выполнено на указанном Keenetic, отдельное испытание Netcraze пока не проведено.

KeenDesk — название этого установщика и документации. Программы сервера и клиент продолжают называться RustDesk; проект не является официальным продуктом RustDesk, Keenetic или Netcraze. См. [происхождение компонентов](../SOURCE-NOTICE.md).
