use types::primitives::Epoch;
use types::types::{AttestationData, Validator};

// Check if validator is active
pub fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

// Check if validator is slashable
pub fn is_slashable_validator(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && epoch < validator.withdrawable_epoch
        && validator.activation_epoch <= epoch
}

// Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
pub fn is_slashable_attestation_data(data_1: &AttestationData, data_2: &AttestationData) -> bool {
    (data_1 != data_2 && data_1.target.epoch == data_2.target.epoch)
        || (data_1.source.epoch < data_2.source.epoch && data_2.target.epoch < data_1.target.epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::u64::MAX as epoch_max;
    use types::primitives::{PublicKey, SecretKey, H256};
    use types::types::{Checkpoint, Crosslink};

    fn default_validator() -> Validator {
        Validator {
            effective_balance: 0,
            slashed: false,
            activation_eligibility_epoch: epoch_max,
            activation_epoch: epoch_max,
            exit_epoch: epoch_max,
            withdrawable_epoch: epoch_max,
            withdrawal_credentials: H256([0; 32]),
            pubkey: PublicKey::from_secret_key(&SecretKey::random()),
        }
    }

    fn default_crosslink() -> Crosslink {
        Crosslink {
            shard: 0,
            parent_root: H256([0; 32]),
            start_epoch: 0,
            end_epoch: 1,
            data_root: H256([0; 32]),
        }
    }

    fn default_attestation_data() -> AttestationData {
        AttestationData {
            beacon_block_root: H256([0; 32]),
            source: Checkpoint {
                epoch: 0,
                root: H256([0; 32]),
            },
            target: Checkpoint {
                epoch: 0,
                root: H256([0; 32]),
            },
            crosslink: default_crosslink(),
        }
    }

    #[test]
    fn test_not_activated() {
        let validator = default_validator();
        let epoch: u64 = 10;

        assert!(!is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_activated() {
        let mut validator = default_validator();
        validator.activation_epoch = 4;
        let epoch: u64 = 10;

        assert!(is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_exited() {
        let mut validator = default_validator();
        validator.activation_epoch = 1;
        validator.exit_epoch = 10;
        let epoch: u64 = 10;

        assert!(!is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_already_slashed() {
        let mut validator = default_validator();
        validator.activation_epoch = 1;
        validator.slashed = true;
        let epoch: u64 = 10;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_not_slashable_not_active() {
        let validator = default_validator();
        let epoch: u64 = 10;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_not_slashable_withdrawable() {
        let mut validator = default_validator();
        validator.activation_epoch = 1;
        validator.withdrawable_epoch = 9;
        let epoch: u64 = 10;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_slashable() {
        let mut validator = default_validator();
        validator.activation_epoch = 1;
        validator.withdrawable_epoch = 11;
        let epoch: u64 = 10;

        assert!(is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_double_vote_attestation_data() {
        let mut data_1 = default_attestation_data();
        let data_2 = default_attestation_data();
        data_1.target.root = H256([1; 32]);

        assert!(is_slashable_attestation_data(&data_1, &data_2));
    }

    #[test]
    fn test_equal_attestation_data() {
        let data_1 = default_attestation_data();
        let data_2 = default_attestation_data();

        assert!(!is_slashable_attestation_data(&data_1, &data_2));
    }

    #[test]
    fn test_surround_vote_attestation_data() {
        let mut data_1 = default_attestation_data();
        let mut data_2 = default_attestation_data();
        data_1.source.epoch = 0;
        data_2.source.epoch = 1;
        data_1.target.epoch = 4;
        data_2.target.epoch = 3;

        assert!(is_slashable_attestation_data(&data_1, &data_2));
    }

    #[test]
    fn test_not_slashable_attestation_data() {
        let mut data_1 = default_attestation_data();
        let mut data_2 = default_attestation_data();
        data_1.source.epoch = 0;
        data_1.target.epoch = 4;
        data_2.source.epoch = 4;
        data_2.target.epoch = 5;
        data_2.source.root = H256([1; 32]);
        data_2.target.root = H256([1; 32]);

        assert!(!is_slashable_attestation_data(&data_1, &data_2));
    }
}
