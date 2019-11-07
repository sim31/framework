use types::beacon_state::BeaconState;
use types::config::Config;
use types::primitives::{Gwei, ValidatorIndex};
use crate::error::Error;

// ok
pub fn increase_balance<C: Config>(
    _state: &mut BeaconState<C>,
    _index: ValidatorIndex,
    _delta: Gwei,
) -> Result<(), Error> {
    Ok(())
}

// ok
pub fn decrease_balance<C: Config>(
    _state: &mut BeaconState<C>,
    _index: ValidatorIndex,
    _delta: Gwei,
) -> Result<(), Error> {
    Ok(())
}

// ok
pub fn initiate_validator_exit<C: Config>(_state: &mut BeaconState<C>, _index: ValidatorIndex) -> Result<(), Error> {
    Ok(())
}

// ok
pub fn slash_validator<C: Config>(_state: &mut BeaconState<C>, _index: ValidatorIndex) -> Result<(), Error> {
    Ok(())
}
