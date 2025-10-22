# VRackRemote - Библиотека для работы с VRack2 API

Библиотека для взаимодействия с VRack2 сервером через защищенное соединение с поддержкой шифрования, команд и широковещательных каналов.

Для работы с API VRack2 - рекомендуется ознакомиься с документом [VRack2 API](https://github.com/VRack2/vrack2/blob/main/docs/Api.md)

## Установка

```bash
npm install vrack2-remote
```

## Основные возможности

- Защищенное соединение с AES-CBC шифрованием
- Поддержка команд и ответов с таймаутами
- Широковещательные каналы (pub/sub)
- Двухэтапная аутентификация (API key + приватный ключ)
- Автоматическая очередь команд с таймаутами
- Контроль уровня доступа к командам

## Быстрый старт

### Подключение и аутентификация

```javascript
import VRackRemoteWeb from 'vrack2-remote'

// Создаем экземпляр (укажите ваш API ключ и приватный ключ)
const remote = new VRackRemoteWeb('ws://localhost:4044','ваш_api_ключ', 'ваш_приватный_ключ')

// Или можно указать ключи после создания
remote.setKey(this.connection.secret)
remote.setPrivateKey(this.connection.private)
// Или поменять установить хост после создания
remote.host = 'ws://localhost:4044'

// Настройка обработчиков событий
remote.on('open', () => console.log('Соединение установлено'))
remote.on('close', () => console.log('Соединение закрыто'))
remote.on('error', (err) => console.error('Ошибка:', err))
try {
    // Соединение с сервером - Ожидание ответа
    await this.remote.connect()
    //  Авторизация - Отправка секретного ключа серверу
    await this.remote.apiKeyAuth()
    // Обновление списка комманд для проверки доступа к командам
    await this.remote.commandsListUpdate()
}catch (error){
    console.error(error)
}
```

### Работа с командами

```javascript
// Выполнение команды
try {
  const services = await this.remote.command('serviceUpdateList', {})
  console.log('Результат:', services)
} catch (e) {
  console.error('Ошибка команды:', e)
}

// Проверка уровня доступа
if (remote.checkAccess('serviceUpdateList')) {
  // Выполнение привилегированной команды
}
```

### Работа с каналами

**На один канал можно подключить только одну callback функцию. Вы можете повесить свой обработчик, который будет обрабатывать несколько callback функций.**

```javascript
// Подписка на канал
await remote.channelJoin('services.service.devices.DeviceID.render', (data) => {
  console.log('Новое уведомление:', data)
})

// Отписка от канала
await remote.channelLeave('services.service.devices.DeviceID.render')
```

## API

### Основные методы

- `setKey(key)` - Установить API ключ
- `setPrivateKey(privateKey)` - Установить приватный ключ
- `command(command, params)` - Выполнить команду
  - `command` - Название команды
  - `params` - Параметры команды (объект)
- `channelJoin(channel, callback)` - Подписаться на канал
- `channelLeave(channel)` - Отписаться от канала
- `apiKeyAuth()` - Аутентификация по API ключу
- `commandsListUpdate()` - Обновить список доступных команд
- `checkAccess(command)` - Проверить доступ к команде

### События

- `open` - Соединение установлено
- `close` - Соединение закрыто
- `error` - Произошла ошибка

### Флаги/Дополнительные данные

Можно получить доступ через экземпляр класса соединения: 
```ts
if (remote.connected) {} // ... 
```

 - `connected` - Флаг успешного подключения
 - `connection` - Флаг подключения в процессе
 - `cipher` - Флаг использования шифрования
 - `level` - Текущий уровень доступа (1000,3,2,1)
 - `commandsList` - Список доступных комманд


Набросок простого компонента для получения онлайн данных на Vue3:

```vue
<template>
  <div>
    <h2>Монитор SmartBulb</h2>
    <p>Статус: <strong>{{ status }}</strong></p>

    <div v-if="rawData" class="data-container">
      <pre>{{ rawData }}</pre>
    </div>
    <div v-else>
      <p>Ожидание данных...</p>
    </div>
  </div>
</template>

<script>
import { ref, inject } from 'vue'
import VRackRemoteWeb from 'vrack2-remote'

export default {
  name: 'SmartBulbMonitor',

  setup() {
    const rawData = ref(null)
    const status = ref('disconnected')
    return {
      rawData,
      status
    }
  },

  data() {
    return {
      remote: null,
      HOST: 'ws://localhost:4044',
      API_KEY: 'ваш_api_ключ',
      PRIVATE_KEY: 'ваш_приватный_ключ'
    }
  },

  watch: {
    status(newStatus) {
      // Можно добавить логику при изменении статуса, если нужно
      console.log('Статус соединения:', newStatus)
    }
  },

  mounted() {
    this.connect()
  },

  methods: {

    handleChannelData(data) {
      this.rawData = data
    },

    async connect() {
      try {
        this.status = 'connecting'

        // Создаем новый экземпляр соединения
        this.remote = new VRackRemoteWeb(this.HOST, this.API_KEY, this.PRIVATE_KEY)

        this.remote.on('open', () => {
          console.log('Соединение установлено')
        })

        this.remote.on('close', () => {
          console.log('Соединение закрыто')
          this.status = 'disconnected'
        })

        this.remote.on('error', (err) => {
          console.error('Ошибка соединения:', err)
          this.status = 'error'
        })

        // Попытка соединения
        await this.remote.connect()
        // Авторизация - отправка ключей и тп
        await this.remote.apiKeyAuth()
        // Обновление списка доступных команд с правами
        await this.remote.commandsListUpdate()
        // Подписываемся на канал и устанавливаем обработчик обновленных данных
        await this.remote.channelJoin('services.smart-light.devices.SmartBulb.render', this.handleChannelData)
        this.status = 'connected'
      } catch (error) {
        console.error('Ошибка при подключении:', error)
        this.status = 'error'
      }
    },

    async disconnect() {
      if (!this.remote) return
      this.remote = null
      this.status = 'disconnected'
    }
  }
}
</script>

<style scoped>
.data-container {
  background: #f5f5f5;
  padding: 12px;
  margin-top: 12px;
  font-family: monospace;
}

pre {
  margin: 0;
  white-space: pre-wrap;
}
</style>
```