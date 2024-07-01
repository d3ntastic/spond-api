# Spond Package

This package provides a unofficial TypeScript class `Spond` that allows you to interact with the Spond API. It includes functionalities for logging in, fetching groups and events, managing chats, and more. This package was inspired by [Spond](https://github.com/Olen/Spond), a python package, which extracted the Spond API calls, which this Node.js package is using aswell. This package is basically just a translation of [Spond](https://github.com/Olen/Spond).


## Installation

```sh
npm install spond
```

## Usage

### Importing the Module

```typescript
import { Spond } from 'spond';
```

### Creating an Instance

Create an instance of the Spond class by providing your Spond username and password.

```typescript
const spond = new Spond('your_username', 'your_password');
```

### Methods

Below are the available methods and their usage.

#### `loginChat()`

Logs in to the chat system and sets the chatUrl and auth properties.

```typescript
await spond.loginChat();
```

#### `getGroups(params: GetGroupsParams = {})`

Fetches all groups.

- `params` (optional): An object with optional properties.

```typescript
const groups = await spond.getGroups();
```

#### `getGroup(params: { uid: string })`

Fetches a specific group by its unique identifier.

- `params`:
    - `uid`: The unique identifier of the group.

```typescript
const group = await spond.getGroup({ uid: 'group_id' });
```

#### `getPerson(params: GetPersonParams)`

Fetches a person by their identifier.

- `params`:
    - `user`: The user's identifier.

```typescript
const person = await spond.getPerson({ user: 'user_id' });
```

#### `getMessages()`

Fetches messages from the chat system.

```typescript
const messages = await spond.getMessages();
```

#### `continueChat(params: { chatId: string, text: string })`

Continues a chat by sending a message.

- `params`:
    - `chatId`: The chat ID.
    - `text`: The message text.

```typescript
const response = await spond.continueChat({ chatId: 'chat_id', text: 'Hello!' });
```

#### `sendMessage(params: { text: string, user?: string, groupUid?: string, chatId?: string })`

Sends a message. If `chatId` is provided, continues the chat, otherwise sends a new message to a user in a group.

- `params`:
    - `text`: The message text.
    - `user` (optional): The user ID.
    - `groupUid` (optional): The group ID.
    - `chatId` (optional): The chat ID.

```typescript
const response = await spond.sendMessage({ text: 'Hello!', user: 'user_id', groupUid: 'group_id' });
```

#### `getEvents(params: GetEventsParams = {})`

Fetches events.

- `params` (optional): An object with optional properties:
    - `groupId`: The group ID.
    - `subgroupId`: The subgroup ID.
    - `includeScheduled`: Whether to include scheduled events.
    - `maxEnd`: The maximum end date.
    - `minEnd`: The minimum end date.
    - `maxStart`: The maximum start date.
    - `minStart`: The minimum start date.
    - `maxEvents`: The maximum number of events to fetch.

```typescript
const events = await spond.getEvents({ groupId: 'group_id', maxEvents: 50 });
```

#### `getEvent(params: { uid: string })`

Fetches a specific event by its unique identifier.

- `params`:
    - `uid`: The unique identifier of the event.

```typescript
const event = await spond.getEvent({ uid: 'event_id' });
```

#### `updateEvent(params: UpdateEventParams)`

Updates an event with the provided data.

- `params`:
    - `uid`: The unique identifier of the event.
    - `updates`: An object containing the updates.

```typescript
const updatedEvent = await spond.updateEvent({ uid: 'event_id', updates: { heading: 'New Heading' } });
```

#### `getEventAttendanceXlsx(params: { uid: string })`

Fetches the attendance data for an event in XLSX format.

- `params`:
    - `uid`: The unique identifier of the event.

```typescript
const attendanceXlsx = await spond.getEventAttendanceXlsx({ uid: 'event_id' });
```

#### `changeResponse(params: { uid: string, user: string, payload: any })`

Changes the response of a user for a specific event.

- `params`:
    - `uid`: The unique identifier of the event.
    - `user`: The user ID.
    - `payload`: The payload containing the new response.

```typescript
const response = await spond.changeResponse({ uid: 'event_id', user: 'user_id', payload: { status: 'going' } });
```

### Error Handling

The Spond class methods throw errors if the API calls fail. Ensure to use try...catch blocks to handle these errors gracefully.

```typescript
try {
    const groups = await spond.getGroups();
} catch (error) {
    console.error('Failed to fetch groups:', error);
}
```

## License

This project is licensed under the MIT License.
