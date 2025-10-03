# Генерация фаззинг-оберток с использованием LLM

## Обзор

Futag теперь поддерживает генерацию фаззинг-оберток с использованием больших языковых моделей (LLM), аналогично проекту [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen). Эта функция использует передовые языковые модели для автоматической генерации качественных фаззинг-оберток.

## Основные возможности

- **Несколько провайдеров LLM**: Поддержка OpenAI (GPT-4, GPT-3.5-turbo), Anthropic (Claude), Ollama и OpenAI-совместимых локальных серверов
- **Поддержка локальных LLM**: Работа полностью оффлайн с Ollama, LM Studio или другими локальными моделями
- **Умная генерация кода**: Использует продвинутые промпты для генерации качественных фаззинг-оберток
- **Гибкая интеграция**: Может использоваться отдельно или в комбинации с традиционным статическим анализом
- **Настраиваемость**: Регулируемые параметры temperature, max tokens и выбор модели
- **Защита приватности**: Храните свой код в безопасности с локальными LLM

## Установка

### Зависимости для облачных LLM

Установите необходимые зависимости для облачных LLM:

```bash
pip install openai anthropic
```

Или используйте файл requirements:

```bash
cd src/python/futag-package
pip install -r requirements.txt
```

### Настройка локальных LLM

Для локальных LLM нужна библиотека `requests` (включена в requirements.txt):

```bash
pip install requests
```

#### Вариант 1: Ollama (Рекомендуется)

1. **Установите Ollama**: Скачайте с https://ollama.ai/download
2. **Запустите сервер Ollama**:
   ```bash
   ollama serve
   ```
3. **Загрузите модель** (рекомендуемые модели для генерации кода):
   ```bash
   # Лучше всего для генерации кода
   ollama pull codellama:13b
   
   # Альтернативы
   ollama pull deepseek-coder:6.7b
   ollama pull mistral
   ollama pull llama2:13b
   ```

#### Вариант 2: LM Studio

1. **Скачайте LM Studio**: https://lmstudio.ai/
2. **Загрузите модель**: Скачайте и загрузите CodeLlama, Mistral или DeepSeek Coder
3. **Запустите локальный сервер**: Нажмите "Start Server" (по умолчанию: http://localhost:1234)

#### Вариант 3: Другие OpenAI-совместимые серверы

Вы можете использовать любой OpenAI-совместимый локальный сервер:
- LocalAI: https://localai.io/
- text-generation-webui: https://github.com/oobabooga/text-generation-webui
- vLLM: https://github.com/vllm-project/vllm

## Быстрый старт

### 1. Настройка API ключа

Установите API ключ как переменную окружения:

```bash
# Для OpenAI
export OPENAI_API_KEY="ваш-ключ-openai"

# Для Anthropic
export ANTHROPIC_API_KEY="ваш-ключ-anthropic"
```

### 2. Базовое использование

```python
from futag.preprocessor import Builder
from futag.generator import Generator

# Сборка и анализ библиотеки
builder = Builder("futag-llvm/", "путь/к/библиотеке/")
builder.auto_build()
builder.analyze()

# Генерация фаззинг-оберток с помощью LLM
generator = Generator("futag-llvm/", "путь/к/библиотеке/")
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=10
)

print(f"Сгенерировано {stats['successful']} фаззинг-оберток")
```

## Продвинутое использование

### Использование различных провайдеров LLM

#### Локальные LLM с Ollama (API ключ не требуется!)

```python
# Использование CodeLlama (лучше всего для генерации кода)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="codellama:13b",  # или codellama:7b, codellama:34b
    max_functions=10,
    temperature=0.2,  # Ниже для более детерминированного кода
    max_tokens=2048
)

# Использование DeepSeek Coder (специализирован на коде)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="deepseek-coder:6.7b",
    max_functions=10,
    temperature=0.2
)

# Использование Mistral (сбалансированная производительность)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="mistral",
    max_functions=10,
    temperature=0.3
)
```

#### Локальные LLM с LM Studio или OpenAI-совместимым сервером

```python
# Установите переменную окружения для пользовательского хоста (опционально)
# export LOCAL_LLM_HOST="http://localhost:1234"

stats = generator.gen_targets_with_llm(
    llm_provider="local",
    llm_model="local-model",  # Имя модели с вашего сервера
    max_functions=10,
    temperature=0.2,
    max_tokens=2048
)
```

#### OpenAI GPT-4

```python
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    llm_api_key="ваш-ключ",  # Опционально, если установлена переменная окружения
    max_functions=10,
    temperature=0.7,
    max_tokens=2048
)
```

#### OpenAI GPT-3.5-turbo (Быстрее/Дешевле)

```python
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-3.5-turbo",
    max_functions=20,
    temperature=0.5
)
```

#### Anthropic Claude

```python
stats = generator.gen_targets_with_llm(
    llm_provider="anthropic",
    llm_model="claude-3-opus-20240229",
    max_functions=10
)
```

### Гибридный подход: Традиционный + LLM

Комбинируйте традиционный статический анализ с LLM-генерацией:

```python
from futag.generator import Generator

generator = Generator("futag-llvm/", "путь/к/библиотеке/")

# Сначала: Традиционная генерация
generator.gen_targets(anonymous=False, max_wrappers=10)

# Затем: Дополнение LLM-генерацией
llm_stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=5
)

# Компиляция всех целей
generator.compile_targets(workers=4, keep_failed=True)
```

## Параметры конфигурации

### Параметры `gen_targets_with_llm()`

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `llm_provider` | str | "openai" | Провайдер LLM: 'openai', 'anthropic', 'ollama' или 'local' |
| `llm_model` | str | "gpt-4" | Название модели (например, 'gpt-4', 'codellama:13b', 'mistral') |
| `llm_api_key` | str | None | API ключ для облачных провайдеров (не нужен для локальных) |
| `max_functions` | int | None | Максимальное количество функций для генерации (None = все) |
| `temperature` | float | 0.7 | Temperature LLM (0.0-1.0, меньше = более детерминированный) |
| `max_tokens` | int | 2048 | Максимальное количество токенов в ответе LLM |

### Рекомендуемые модели по провайдерам

| Провайдер | Рекомендуемые модели | Применение |
|----------|---------------------|------------|
| **Ollama** | codellama:13b | Лучше всего для генерации кода |
| | deepseek-coder:6.7b | Специалист по коду, хороший баланс |
| | mistral | Универсальная, быстрая |
| | llama2:13b | Универсальная |
| **OpenAI** | gpt-4 | Высочайшее качество |
| | gpt-3.5-turbo | Быстро и экономично |
| **Anthropic** | claude-3-opus-20240229 | Высокое качество |
| | claude-3-sonnet-20240229 | Сбалансированная |
| **Local** | Любая OpenAI-совместимая | Зависит от вашей настройки |

### Руководство по temperature

- **0.0-0.3**: Высокая детерминированность, консервативная генерация (рекомендуется для локальных моделей кода)
- **0.4-0.7**: Сбалансированная креативность и консистентность (хорошо для облачных моделей)
- **0.8-1.0**: Более креативно, но потенциально менее надежно

### Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `OPENAI_API_KEY` | API ключ OpenAI | - |
| `ANTHROPIC_API_KEY` | API ключ Anthropic | - |
| `OLLAMA_HOST` | URL сервера Ollama | http://localhost:11434 |
| `LOCAL_LLM_HOST` | URL локального LLM сервера | http://localhost:1234 |

## Результаты

Сгенерированные обертки сохраняются в:
- `futag-fuzz-drivers/<имя_функции>/<имя_функции>_llm_fuzz.c`
- Статистика: `futag-fuzz-drivers/llm_generation_stats.json`

Пример файла статистики:
```json
{
  "total": 10,
  "successful": 8,
  "failed": 2,
  "successful_functions": ["func1", "func2", ...],
  "failed_functions": ["func3", "func4"]
}
```

## Сравнение: Традиционный vs LLM-подход

### Традиционный статический анализ

**Преимущества:**
- Без затрат на API
- Быстрый и детерминированный
- Работает оффлайн
- Хорошо протестирован и надежен

**Недостатки:**
- Может испытывать трудности со сложными типами
- Ограничен предопределенными шаблонами
- Менее гибкий

### Облачная LLM-генерация

**Преимущества:**
- Лучше справляется со сложными сценариями
- Более гибкий и адаптивный
- Может учиться на контексте
- Похож на написанные человеком обертки
- Высочайшее качество результата

**Недостатки:**
- Требует доступа к API и стоит денег ($0.01-$0.15 за функцию)
- Недетерминированный (варьируется между запусками)
- Требуется интернет-соединение
- Сгенерированный код следует проверять
- Проблемы конфиденциальности (данные отправляются в облако)

### Локальная LLM-генерация (НОВИНКА!)

**Преимущества:**
- **Бесплатное использование** (без затрат на API)
- **Полная приватность** (данные остаются локально)
- **Интернет не требуется**
- **Неограниченные генерации**
- Полный контроль над моделями
- Хорошее качество с правильными моделями (CodeLlama, DeepSeek)

**Недостатки:**
- Требует локальное оборудование (GPU рекомендуется, но не обязательно)
- Медленнее облачных API
- Немного ниже качество для меньших моделей
- Требуется начальная настройка и загрузка модели
- Требуется место на диске для моделей (4-26 ГБ на модель)

### Рекомендация

Используйте **гибридный подход**:
1. Начните с традиционной генерации для стандартных случаев
2. Используйте локальные LLM (Ollama + CodeLlama) для сложных функций - БЕСПЛАТНО!
3. Используйте облачные LLM (GPT-4) только для самых сложных случаев
4. Проверяйте и тестируйте все сгенерированные обертки

**Экономичная стратегия:**
- Фаза 1: Традиционная генерация (бесплатно, быстро)
- Фаза 2: Локальная LLM генерация (бесплатно, приватно, неограниченно)
- Фаза 3: Облачная LLM для оставшихся сложных случаев (платно, высокое качество)

## Оценка стоимости

Приблизительные цены (на 2024 год):

| Модель | Стоимость за 1M токенов | Примерно на функцию |
|--------|------------------------|---------------------|
| GPT-4 | $30 (вход) / $60 (выход) | $0.05-$0.15 |
| GPT-3.5-turbo | $0.50 (вход) / $1.50 (выход) | $0.01-$0.03 |
| Claude-3-Opus | $15 (вход) / $75 (выход) | $0.03-$0.10 |

**Совет**: Начните с GPT-3.5-turbo для тестирования, затем используйте GPT-4 для продакшена.

## Примеры

Смотрите полные примеры в:
- `src/python/example-llm-generation.py` - Примеры облачных LLM (OpenAI, Anthropic)
- `src/python/example-local-llm-generation.py` - **Примеры локальных LLM (Ollama, LM Studio)**
- `examples/` - Примеры сгенерированных оберток

## Устранение неполадок

### Проблемы с локальными LLM

#### Ошибка подключения к Ollama
```bash
# Проверьте, запущен ли Ollama
curl http://localhost:11434/api/tags

# Запустите Ollama, если не запущен
ollama serve

# Проверьте доступные модели
ollama list
```

#### Модель не найдена
```bash
# Загрузите необходимую модель
ollama pull codellama:13b

# Или посмотрите доступные модели онлайн
ollama search codellama
```

#### Медленная генерация с Ollama
- Используйте GPU для более быстрого вывода
- Используйте меньшие модели (7B вместо 13B)
- Уменьшите параметр max_tokens
- Рассмотрите использование квантованных моделей

#### Проблемы подключения к LM Studio
- Убедитесь, что сервер запущен в LM Studio
- Проверьте порт (по умолчанию: 1234)
- Установите LOCAL_LLM_HOST, если используется другой порт:
  ```bash
  export LOCAL_LLM_HOST="http://localhost:8080"
  ```

### Проблемы с API ключом облачных сервисов

```python
# Проверить, установлены ли зависимости
from futag.llm_generator import check_llm_dependencies
if check_llm_dependencies("openai"):
    print("Зависимости OpenAI доступны")
```

### Распространенные ошибки

1. **ImportError: No module named 'openai'**
   - Решение: `pip install openai`

2. **ImportError: No module named 'requests'**
   - Решение: `pip install requests` (нужен для локальных LLM)

3. **API ключ не найден**
   - Решение: Установите переменную окружения или передайте параметр `llm_api_key`

4. **Ошибки ограничения скорости** (облачные API)
   - Решение: Используйте `max_functions` для ограничения запросов, добавьте задержки между вызовами

5. **Connection refused (Ollama)**
   - Решение: Запустите Ollama с помощью `ollama serve`
   - Проверьте настройки брандмауэра

6. **Модель не найдена (Ollama)**
   - Решение: Загрузите модель с помощью `ollama pull codellama:13b`

7. **Нехватка памяти (локальные LLM)**
   - Решение: Используйте меньшую модель (например, codellama:7b вместо 13b)
   - Закройте другие приложения
   - Рассмотрите облачные API для систем с ограниченными ресурсами

## Будущие улучшения

Планируемые функции:
- [x] Поддержка локальных LLM (Ollama, LM Studio) ✅ **ЗАВЕРШЕНО**
- [ ] Тонко настроенные модели для фаззинга
- [ ] Итеративное улучшение на основе результатов компиляции
- [ ] Интеграция с результатами фаззинга для обратной связи
- [ ] Оптимизация затрат и кеширование
- [ ] Поддержка большего количества провайдеров локальных LLM (vLLM, llama.cpp)
- [ ] Поддержка квантования моделей для более быстрого вывода

## Ссылки

- [Ollama](https://ollama.ai/) - Запуск больших языковых моделей локально
- [LM Studio](https://lmstudio.ai/) - Удобный интерфейс для локальных LLM
- [CodeLlama](https://ai.meta.com/blog/code-llama-large-language-model-coding/) - Специализированная на коде LLM от Meta
- [DeepSeek Coder](https://github.com/deepseek-ai/DeepSeek-Coder) - LLM, ориентированная на код
- [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) - Инструмент фаззинга на основе LLM от Google
- [Документация OpenAI API](https://platform.openai.com/docs)
- [Документация Anthropic API](https://docs.anthropic.com/)
- [Документация LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

## Участие в разработке

Чтобы внести вклад в LLM-генерацию:
1. Тестируйте с различными моделями LLM
2. Улучшайте промпты в `llm_generator.py`
3. Добавляйте поддержку новых провайдеров LLM
4. Делитесь своими результатами и отзывами
