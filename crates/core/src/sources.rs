//! Fixed-size, monotonic-time traffic windows. No per-message history allocation.
use crate::status::SourceStatus;
use std::{collections::BTreeMap, net::IpAddr};

pub const SOURCE_LIMIT: usize = 256;
#[derive(Clone, Copy, Default)]
struct Bucket {
    tick: u64,
    count: u64,
}
struct Source {
    status: SourceStatus,
    seconds: Box<[Bucket; 61]>,
    minutes: Box<[Bucket; 1440]>,
}
#[derive(Default)]
pub struct Sources {
    entries: BTreeMap<IpAddr, Source>,
    pub untracked_messages: u64,
}
impl Sources {
    pub fn received(&mut self, ip: IpAddr, allowed: bool, wall_ms: u64) {
        if !self.entries.contains_key(&ip) && self.entries.len() >= SOURCE_LIMIT {
            self.untracked_messages += 1;
            return;
        }
        let source = self.entries.entry(ip).or_insert_with(|| Source {
            status: SourceStatus {
                ip,
                allowed,
                messages_received: 0,
                messages_forwarded: 0,
                messages_dropped: 0,
                messages_per_second: 0,
                messages_per_minute: 0,
                messages_last_24h: 0,
                last_seen_ms: wall_ms,
            },
            seconds: Box::new([Bucket::default(); 61]),
            minutes: Box::new([Bucket::default(); 1440]),
        });
        source.status.messages_received += 1;
        source.status.last_seen_ms = wall_ms;
    }
    pub fn dropped(&mut self, ip: IpAddr) {
        if let Some(source) = self.entries.get_mut(&ip) {
            source.status.messages_dropped += 1;
        }
    }
    pub fn forwarded(&mut self, ip: IpAddr, second: u64) {
        if let Some(source) = self.entries.get_mut(&ip) {
            source.status.messages_forwarded += 1;
            increment(&mut source.seconds[(second % 61) as usize], second);
            let minute = second / 60;
            increment(&mut source.minutes[(minute % 1440) as usize], minute);
        }
    }
    pub fn snapshot(&self, second: u64) -> Vec<SourceStatus> {
        self.entries
            .values()
            .map(|source| {
                let mut status = source.status.clone();
                // Last completed second and last 60 completed seconds. Stable rates
                // independent of the UI's polling phase; idle sources decay to zero.
                status.messages_per_second = source
                    .seconds
                    .iter()
                    .filter(|b| b.tick < second && second - b.tick == 1)
                    .map(|b| b.count)
                    .sum();
                status.messages_per_minute = source
                    .seconds
                    .iter()
                    .filter(|b| b.tick < second && second - b.tick <= 60)
                    .map(|b| b.count)
                    .sum();
                let minute = second / 60;
                // Includes the current minute; oldest boundary has 1-minute precision.
                status.messages_last_24h = source
                    .minutes
                    .iter()
                    .filter(|b| b.tick <= minute && minute - b.tick < 1440)
                    .map(|b| b.count)
                    .sum();
                status
            })
            .collect()
    }
}
fn increment(bucket: &mut Bucket, tick: u64) {
    if bucket.tick != tick {
        *bucket = Bucket { tick, count: 0 };
    }
    bucket.count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_age_out_and_windows_wrap_without_stale_counts() {
        let ip = "127.0.0.1".parse().unwrap();
        let mut sources = Sources::default();
        sources.received(ip, true, 10);
        sources.forwarded(ip, 0);
        sources.forwarded(ip, 0);
        sources.forwarded(ip, 59);
        let s = &sources.snapshot(60)[0];
        assert_eq!(
            (
                s.messages_per_second,
                s.messages_per_minute,
                s.messages_last_24h
            ),
            (1, 3, 3)
        );
        assert_eq!(sources.snapshot(61)[0].messages_per_minute, 1);
        assert_eq!(sources.snapshot(120)[0].messages_per_minute, 0);
        assert_eq!(sources.snapshot(86400)[0].messages_last_24h, 0);
        sources.forwarded(ip, 86400);
        assert_eq!(sources.snapshot(86401)[0].messages_last_24h, 1);
        assert_eq!(sources.snapshot(86401)[0].messages_per_second, 1);
        assert_eq!(sources.snapshot(86401)[0].messages_forwarded, 4);
    }
    #[test]
    fn bounded_tracking_does_not_evict_existing_history() {
        let mut sources = Sources::default();
        for i in 0..=SOURCE_LIMIT {
            sources.received(IpAddr::V4(std::net::Ipv4Addr::from(i as u32)), false, 0);
        }
        assert_eq!(sources.snapshot(0).len(), SOURCE_LIMIT);
        assert_eq!(sources.untracked_messages, 1);
        sources.received(IpAddr::from([0, 0, 0, 0]), false, 10);
        sources.dropped(IpAddr::from([0, 0, 0, 0]));
        assert_eq!(sources.snapshot(0)[0].messages_received, 2);
        assert_eq!(sources.snapshot(0)[0].messages_dropped, 1);
    }
}
