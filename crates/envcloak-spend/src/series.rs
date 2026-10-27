//! 35-bucket daily spend series with `partial` gap marks and observed-day
//! counts (D4-17, M4-02).

use envcloak_core::money::{Iso4217, Money, MoneyError};
use envcloak_core::vault::{MAX_DAILY_BUCKETS, SnapshotBucket};

/// Window length for the "last 30 days" summary (SPEC §8, D4-17).
pub const LAST_30_DAYS_WINDOW: u32 = 30;

/// Minimum observed days required for a "last 30 days" sum (D4-17: below 7
/// reports "not enough data").
pub const MIN_OBSERVED_DAYS_FOR_30D: u8 = 7;

/// Summary of the trailing 30-day window (D4-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Last30DaysSummary {
    EnoughData {
        total: Money,
        observed_days: u8,
        has_partial: bool,
    },
    NotEnoughData {
        observed_days: u8,
    },
}

/// Bounded 35-day daily spend series for one currency (D4-09, D4-17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailySeries {
    currency: Iso4217,
    scale: u8,
    buckets: Vec<SnapshotBucket>,
}

impl DailySeries {
    pub fn new(currency: Iso4217, scale: u8) -> Self {
        DailySeries {
            currency,
            scale,
            buckets: Vec::new(),
        }
    }

    pub fn from_buckets(
        currency: Iso4217,
        scale: u8,
        buckets: Vec<SnapshotBucket>,
    ) -> Result<Self, MoneyError> {
        let mut s = Self::new(currency, scale);
        for b in buckets {
            if b.spend.currency() != currency {
                return Err(MoneyError::CurrencyMismatch {
                    expected: currency,
                    actual: b.spend.currency(),
                });
            }
            s.upsert_bucket(b)?;
        }
        Ok(s)
    }

    pub fn currency(&self) -> Iso4217 {
        self.currency
    }

    pub fn scale(&self) -> u8 {
        self.scale
    }

    pub fn buckets(&self) -> &[SnapshotBucket] {
        &self.buckets
    }

    pub fn into_buckets(self) -> Vec<SnapshotBucket> {
        self.buckets
    }

    /// Records a single day's resetting counter (e.g. `usage_daily`). Missed
    /// days are left as absent gaps, never filled with zero (D4-17).
    pub fn record_daily(&mut self, day_index: u32, spend: Money) -> Result<(), MoneyError> {
        if spend.currency() != self.currency {
            return Err(MoneyError::CurrencyMismatch {
                expected: self.currency,
                actual: spend.currency(),
            });
        }
        self.upsert_bucket(SnapshotBucket {
            day_index,
            spend,
            partial: false,
        })
    }

    /// Derives daily buckets from the difference of a cumulative counter
    /// (`spend_total`, OpenRouter `usage`) between `prev_day` and `curr_day`,
    /// apportioned evenly across the spanned local days and marked `partial`
    /// when the gap spans more than one day (D4-17).
    pub fn record_cumulative_delta(
        &mut self,
        prev_day: u32,
        prev_total: Money,
        curr_day: u32,
        curr_total: Money,
    ) -> Result<(), MoneyError> {
        if prev_total.currency() != self.currency {
            return Err(MoneyError::CurrencyMismatch {
                expected: self.currency,
                actual: prev_total.currency(),
            });
        }
        if curr_total.currency() != self.currency {
            return Err(MoneyError::CurrencyMismatch {
                expected: self.currency,
                actual: curr_total.currency(),
            });
        }
        let delta = curr_total.checked_sub(&prev_total)?;
        if curr_day <= prev_day {
            let existing = self
                .buckets
                .iter()
                .find(|b| b.day_index == curr_day)
                .copied();
            let combined = match existing {
                Some(b) => b.spend.checked_add(&delta)?,
                None => delta,
            };
            let partial = existing.is_some_and(|b| b.partial);
            return self.upsert_bucket(SnapshotBucket {
                day_index: curr_day,
                spend: combined,
                partial,
            });
        }
        let span = curr_day - prev_day;
        let span_capped = span.min(MAX_DAILY_BUCKETS as u32);
        let start_day = curr_day + 1 - span_capped;
        let partial = span > 1;
        let span_i64 = i64::from(span);
        let base_minor = delta.minor() / span_i64;
        let rem_minor = delta.minor() % span_i64;

        for offset in 0..span_capped {
            let day = start_day + offset;
            // Distribute any remainder minor units to the latest days so the
            // sum across the span equals `delta` when `span <= 35`.
            let from_end = span_capped - 1 - offset;
            let extra = if i64::from(from_end) < rem_minor.abs() {
                rem_minor.signum()
            } else {
                0
            };
            let day_minor = base_minor
                .checked_add(extra)
                .ok_or(MoneyError::OutOfBounds)?;
            let day_spend = Money::new(day_minor, delta.scale(), self.currency)?;
            self.upsert_bucket(SnapshotBucket {
                day_index: day,
                spend: day_spend,
                partial,
            })?;
        }
        Ok(())
    }

    fn upsert_bucket(&mut self, bucket: SnapshotBucket) -> Result<(), MoneyError> {
        if bucket.spend.currency() != self.currency {
            return Err(MoneyError::CurrencyMismatch {
                expected: self.currency,
                actual: bucket.spend.currency(),
            });
        }
        match self
            .buckets
            .binary_search_by_key(&bucket.day_index, |b| b.day_index)
        {
            Ok(idx) => {
                self.buckets[idx] = bucket;
            }
            Err(idx) => {
                self.buckets.insert(idx, bucket);
            }
        }
        if self.buckets.len() > MAX_DAILY_BUCKETS {
            let excess = self.buckets.len() - MAX_DAILY_BUCKETS;
            self.buckets.drain(0..excess);
        }
        Ok(())
    }

    /// Computes the trailing 30-day summary ending at `today_day_index`
    /// inclusive (`today_day_index - 29 ..= today_day_index`, D4-17).
    pub fn last_30_days(&self, today_day_index: u32) -> Result<Last30DaysSummary, MoneyError> {
        let first_day = today_day_index.saturating_sub(LAST_30_DAYS_WINDOW - 1);
        let mut total = Money::zero_at_scale(self.scale, self.currency);
        let mut observed_days: u8 = 0;
        let mut has_partial = false;
        for b in &self.buckets {
            if b.day_index >= first_day && b.day_index <= today_day_index {
                total = total.checked_add(&b.spend)?;
                observed_days = observed_days.saturating_add(1);
                if b.partial {
                    has_partial = true;
                }
            }
        }
        if observed_days < MIN_OBSERVED_DAYS_FOR_30D {
            Ok(Last30DaysSummary::NotEnoughData { observed_days })
        } else {
            Ok(Last30DaysSummary::EnoughData {
                total,
                observed_days,
                has_partial,
            })
        }
    }
}
