# Polymarket Odds

Fetches real-time prediction market odds from Polymarket.

## Usage

Call `get_odds(market_id)` to retrieve current probabilities for any active market.

## Parameters

- `market_id` (string): The Polymarket market identifier (e.g., `will-bitcoin-reach-100k-2025`)

## Returns

A JSON object with `yes_probability`, `no_probability`, and `volume_24h`.

## Examples

Get current odds on a market:
```
get_odds("presidential-election-2028")
```

## Notes

Data is sourced from the Polymarket public API. Results are cached for 30 seconds to avoid rate limiting.
