# Запуск

## Сборка

```bash
cmake -S . -B build
cmake --build build
```

## Поднять проект одной командой

```bash
./run_project.sh --demo
```

## Тесты

```bash
ctest --test-dir build --output-on-failure
```

## Запуск сервера

```bash
./build/scan_server configs/patterns.conf.example 9090
```

## Запуск клиента

```bash
./build/scan_client /path/to/file.txt 9090
```

## Запуск утилиты статистики

```bash
./build/scan_stats 9090
```
