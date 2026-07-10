import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject, EMPTY, timer, merge, fromEvent } from 'rxjs';
import { catchError, retry, share, tap, switchMap, startWith, scan, shareReplay, map, timeout, bufferTime, filter, distinctUntilChanged } from 'rxjs/operators';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { SystemInfo as ISystemInfo } from 'src/app/generated/models';
import { SystemApiService } from './system.service';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class LiveDataService {
  private socket$: WebSocketSubject<any> | null = null;
  private updates$ = new Subject<Partial<ISystemInfo>>();
  
  // Shared info stream for the whole app
  public readonly info$: Observable<ISystemInfo>;
  
  // Connection status for the UI
  private connectedSubject = new BehaviorSubject<boolean>(false);
  public connected$ = this.connectedSubject.asObservable();

  constructor(
    private systemService: SystemApiService
  ) {
    // Visibility stream for polling adjustments
    const visibility$ = fromEvent(document, 'visibilitychange').pipe(
      map(() => document.visibilityState),
      startWith(document.visibilityState),
      distinctUntilChanged(),
      shareReplay(1)
    );

    // Periodic polling fallback (adjust frequency based on visibility)
    const fallbackPolling$ = visibility$.pipe(
      switchMap(state => {
        const interval = state === 'visible' ? 5000 : 60000; // 5s when visible, 60s when hidden
        return timer(interval, interval).pipe(
          switchMap(() => {
            // Only poll if not connected OR if backgrounded (to keep data fresh)
            if (this.connectedSubject.value && state === 'visible') return EMPTY;
            // Catch per request: a single failed poll must not tear down the
            // polling stream for the rest of the session
            return this.systemService.getInfo().pipe(catchError(() => EMPTY));
          })
        );
      })
    );

    const updates$ = merge(
      this.connect().pipe(switchMap(() => EMPTY), catchError(() => EMPTY)),
      this.updates$.pipe(
        // Buffer updates to handle bursts when tab is resumed
        bufferTime(500),
        filter(msgs => msgs.length > 0),
        map(msgs => msgs.reduce((acc, curr) => ({ ...acc, ...curr }), {} as Partial<ISystemInfo>))
      ),
      fallbackPolling$
    );

    const initialInfo$ = this.systemService.getInfo().pipe(
      // The first paint depends on this call; retry a few times before
      // leaving it to the websocket / fallback polling
      retry({ count: 3, delay: 2000 }),
      catchError(err => {
        console.error('Initial info fetch failed', err);
        return EMPTY;
      })
    );

    this.info$ = merge(initialInfo$, updates$).pipe(
      scan((acc: ISystemInfo, curr: Partial<ISystemInfo>) => ({ ...acc, ...curr } as ISystemInfo), {} as ISystemInfo),
      // Ensure we have at least once received a message with a recognizable field before emitting
      filter(info => !!info.version || !!info.uptimeSeconds),
      shareReplay(1)
    );
  }

  private connect(): Observable<any> {
    if (environment.mock || this.socket$ || !window.location.host) {
      return EMPTY;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const url = `${protocol}//${host}/api/ws/live`;

    this.socket$ = webSocket({
      url,
      openObserver: {
        next: () => {
          console.log('Live WebSocket connected');
          this.connectedSubject.next(true);
        }
      },
      closeObserver: {
        next: () => {
          console.log('Live WebSocket disconnected');
          this.connectedSubject.next(false);
          this.socket$ = null;
        }
      }
    });

    return this.socket$.pipe(
      timeout(5000),
      tap(msg => {
        if (msg.event === 'update' && msg.data) {
          this.updates$.next(msg.data);
        }
      }),
      retry({
        // A long-lived connection that drops should reconnect quickly again,
        // so reset the backoff after each successful connection
        resetOnSuccess: true,
        delay: (_error, retryCount) => {
          this.connectedSubject.next(false);
          // Exponential backoff with jitter, capped at 30s, so a rebooting
          // device isn't hammered by a fixed-rate retry loop
          const base = Math.min(30000, 2500 * Math.pow(2, Math.min(retryCount - 1, 4)));
          return timer(base * (0.75 + Math.random() * 0.5));
        }
      }),
      share()
    );
  }
}
