# ntfy Notification Module

An Ignition module that adds support for sending alarm notifications through a ntfy server. ntfy is a self hosted server for sending push messages.

See [ntfy](https://ntfy.sh) for more details on the service.

Open Source
---------------

The ntfy module is an open source project distributed under the Apache 2.0 license. Please feel free to download the source code and contribute. 

Getting Started
---------------

1. Download the latest version module (.modl) from [releases](https://github.com/Kyvis-Labs/ignition-ntfy-module/releases)
2. Install the module into Ignition 8.1+
3. Add a new alarm notification profile in the Gateway configuration section (under Alarming > Notification)
4. Select ntfy Notification
5. Enter your ntfy base URL (see below for more details)
6. Add your ntfy api token to the user's contact info
7. Ensure your user is in the on-call roster
8. Use the ntfy profile in your alarm notification pipeline
9. Enjoy!

User Contact Info
---------------

The module adds a new contact info type, called `ntfy Topic`. This topic can be unique or shared between users, and is configured in the ntfy server.

Example User Device Name:  ```notifications```

Make sure to set the contact info for each user you want to notify.

Notification Block Properties
---------------

The profile has 5 properties you can set in the notification block in the alarm notification pipeline:

| Property            | Description                                                                                |
| :-------------------| :------------------------------------------------------------------------------------------|
| `Message`           | The message to send, if no custom alarm message is defined.                                |
| `Throttled Message` | The message to send if throttling is turned.                                               |
| `Title`             | The title of the message in the ntfy app.                                                  |
| `Priority`          | The priority of the message, affects how the message is presented to the user.             |
| `Tags`              | Informative tags or emojis to add to the notification.                                     |
| `Click Action`      | The URL to open when the notification is clicked.                                          |
| `Actions`           | Buttons to add to allow interaction with the notification.                                 |
| `Icon`              | Adds an icon to the notification. (Android Only)                                           |
| `Test Mode`         | Test mode. When true the message is not sent to ntfy but logged in the console.            |

### `Message`
The `Message` property defines the message to send. The message is dynamic using Ignition's Expression language. Defaults to:

```At {eventTime|hh:mm:ss}, alarm "{name}" at "{displayPath}" transitioned to {eventState}.```

### `Throttled Message`
The `Throttled Message` property defines the throttled message to send when consolidation is turned on. The message is dynamic using Ignition's Expression language. Defaults to:

```{alarmEvents.Count} alarm events have occurred.```

### `Title`
The `Title` property defines the title of the message in the ntfy app. The title is optional. If empty, the app's name in ntfy is used. More information can be found [here](https://docs.ntfy.sh/publish/#message-title)

### `Priority`
The `Priority` property defines the priority of the message. On Android, you can set custom notification sounds and vibration patterns on your phone to map to these priorities.  More information can be found [here](https://docs.ntfy.sh/publish/#message-priority)

| Priority                                      | ntfy Priority  | Android Pattern | iPhone Pattern |
| :---------------------------------------------| :----------------| :-- | :-- |
| `Min Priority`                    | `min`              |  `No vibration or sound. The notification will be under the fold in "Other notifications".` | `?` |
| `Low Priority`                    | `low`              |  `No vibration or sound. Notification will not visibly show up until notification drawer is pulled down.` | `?` |
| `Default Priority`                    | `default`              |  `Short default vibration and sound. Default notification behavior.` | `?` |
| `High Priority`                    | `high`              |  `Long vibration burst, default notification sound with a pop-over notification.` | `?` |
| `Max Priority`                    | `max`              |  `Really long vibration bursts, default notification sound with a pop-over notification.` | `?` |

### `Tags`
The `Tags` property adds relevant strings and emojies to the notifications. This is a comman separated listed.  If the tag matches an [emoji shortcode](https://docs.ntfy.sh/emojis/), it will be converted to an emoji and prepended to the title or message.  If the tag does not match, it will be listed below the notification.  More information can be found [here](https://docs.ntfy.sh/publish/#tags-emojis)

#### Example
```+1,no_entry```

### `Click Action`
The `Click Action` defines which URL to open when a notification is clicked.  More information about this functionality can be found [here](https://docs.ntfy.sh/publish/#click-action)

#### Example
```https://www.kyvislabs.com/```

### `Actions`
The `Actions` property adds buttons to notifications, allowing for direct interaction with the notification.  More information about this functionality can be found [here](https://docs.ntfy.sh/publish/#action-buttons)

This functionality will change in the near future, as we will be adding the ability to acknowledge alarms via this functionality.  For the time being, please only add two action buttons, as there is a maximum of three and we will be utilizing one for acknowledging alarms.

#### Example
```view, Open Kyvis Labs, https://www.kyvislabs.com, clear=true```

### `Attach`
The `Attach` property allows you to send files to your phone as part of the notification.  More information can be found [here](https://docs.ntfy.sh/publish/#attachments)

Currently, only external urls are supported and not files from the local file system

#### Example
```https://www.reddit.com/message/messages```

### `Icon`
The `Icon` property will allow for including an icon that will show beside the notification.  More information can be found [here](https://docs.ntfy.sh/publish/#icons)

### `Test Mode`
The `Test Mode` property defines the whether or not to run in test mode. If false, the message is sent normally. If true, the message will only be logged through the Ignition console.

Tag Alarm Properties
---------------

The module provides 3 additional alarm properties on each alarm.  They allow per alarm customization of the message.  If a property is set, it overrides the notification block setting.  The property value is dynamic using Ignition's Expression language.

| Property           | Description                                                                                                                        |
| :------------------| :----------------------------------------------------------------------------------------------------------------------------------|
| Custom Title       | If specified, will be used for the ntfy message title. If blank, the title defined in the notification block will be used.       |
| Custom Message     | If specified, will be used for the ntfy message body. If blank, the message defined in the notification block will be used.      |
| Custom Priority    | If specified, will be used for the ntfy message priority. If blank, the priority defined in the notification block will be used. |
| Custom Tags    | If specified, will be used for the ntfy message tags. If blank, the priority defined in the notification block will be used. |