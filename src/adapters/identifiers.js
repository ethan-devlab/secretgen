import { nanoid } from 'nanoid';
import { v7 } from 'uuid';

export function generateNanoId(length) {
  return nanoid(length);
}

export function generateUuidV7() {
  return v7();
}
