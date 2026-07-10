import { Injectable } from '@angular/core';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';

@Injectable({
  providedIn: 'root'
})
export class WebsocketService {

  public ws$: WebSocketSubject<string>;

  constructor() {
    // Match the page protocol: plain ws: on a wss page is blocked by browsers
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws$ = webSocket({
      url: `${protocol}//${window.location.host}/api/ws`,
      deserializer: (e: MessageEvent) => { return e.data }
    });
  }
}
