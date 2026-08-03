use opencsv_bitcoin::fee_model::estimate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let feerates: Vec<u32> = if std::env::args().len() == 1 {
        vec![1, 3, 10, 25]
    } else {
        std::env::args()
            .skip(1)
            .map(|value| value.parse())
            .collect::<Result<_, _>>()?
    };
    println!(
        "participants,feerate_sat_vb,solo_max_vbytes,batch_max_vbytes,solo_total_sats,batch_total_sats,savings_sats,batch_charge_floor,batch_charge_ceiling"
    );
    for feerate in feerates {
        for participants in [1, 2, 4, 8, 16, 32, 64] {
            let row = estimate(participants, feerate)?;
            println!(
                "{},{},{},{},{},{},{},{},{}",
                row.participants,
                row.feerate_sat_vb,
                row.solo_max_vbytes,
                row.batch_max_vbytes,
                row.solo_total_charge,
                row.batch_total_charge,
                row.solo_minus_batch_sats,
                row.batch_charge_floor,
                row.batch_charge_ceiling,
            );
        }
    }
    Ok(())
}
