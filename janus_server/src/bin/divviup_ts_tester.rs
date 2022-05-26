use std::str::FromStr;

use assert_matches::assert_matches;
use janus::{
    hpke::{self, associated_data_for_report_share, HpkeApplicationInfo, HpkePrivateKey, Label},
    message::{
        HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Nonce, Report,
        Role, TaskId,
    },
};
use janus_test_util::{PrepareTransition, VdafTranscript};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        Aggregator, Collector, Vdaf, VdafError,
    },
};

#[tokio::main]
async fn main() {
    // Task ID.
    let task_id = TaskId::new(
        base64::decode_config(
            "qKjkrnvLh5z2OxBTjMMMSkudVpJX_ESpbsK0a6IIqKo",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    );
    println!("task_id = {}", task_id);
    println!();

    // Leader HPKE config/key.
    let leader_hpke_public_key = HpkePublicKey::new(
        hex::decode("e093d43d77c3970f69d41c27158031e20f43e4314d0308e8769713401ee54a15").unwrap(),
    );
    let leader_hpke_config = HpkeConfig::new(
        HpkeConfigId::from(203),
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
        leader_hpke_public_key,
    );
    let leader_hpke_private_key = HpkePrivateKey::from_str(
        "b07f0c163f8427273df461114621d6b55708579c3544d41a2d06339bc69a5f66",
    )
    .unwrap();
    println!("Leader config & private key:");
    print_hpke_config_and_private_key(&leader_hpke_config, &leader_hpke_private_key);
    println!();

    // Helper HPKE config/key.
    let helper_hpke_public_key = HpkePublicKey::new(
        hex::decode("f39638346735415b9dd4e0e19ed5a9442ba73998550ba87c3f15b9834466f249").unwrap(),
    );
    let helper_hpke_config = HpkeConfig::new(
        HpkeConfigId::from(7),
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
        helper_hpke_public_key,
    );
    let helper_hpke_private_key = HpkePrivateKey::from_str(
        "5879df19f7c7b184aeb97c8eba6af1fdd6d7755762bc49a0516d3b186505937c",
    )
    .unwrap();
    println!("Helper config & private key:");
    print_hpke_config_and_private_key(&helper_hpke_config, &helper_hpke_private_key);
    println!();

    // Decode report.
    //const ENCODED_REPORT: &str = "a8a8e4ae7bcb879cf63b10538cc30c4a4b9d569257fc44a96ec2b46ba208a8aa000000006290037feb32e8f6eabfed4a000000bacb0020e27c51f94fdb6ce53ca338bd2781eb91225f40a7c2fcbdbe74eefe6b125e0e4a0040ed54bad9fc4e6681c134e68c37c93f60c7f8373ad5c71bc78362785de3ef4145b975e3a206b228bc22e4442cfbaa920d0d553c47bec71cd8e3bdafe8be0c90ea070020ce86d537ec528ad5e10e122b2c30e50150d75ac1b11e824656de53f50dfbee35003072f30c2953728ff87a06dc137a272c51ca8924173cc7c1afb3d28aeed7bb086076cfba2e269dfd50428a6965ca19e36c"; // Prio3Aes128Count
    // const ENCODED_REPORT: &str = "a8a8e4ae7bcb879cf63b10538cc30c4a4b9d569257fc44a96ec2b46ba208a8aa00000000628fe88086a56f33074741fa000005cacb002045194585556e5242aa57c8587b4d76754d78b90de2d3797daa905626cd8838790530ece154524d45576cd2ab9f81c5a52404779c045d3bdd4ad3a281e62281c53b11f3e669594f0a12164a46cd38b9075260754b8fe599aeadf62f3c24eaaa7dca39208d8ce0c20fde5697c4b5de2abbdc421459d7b7639da18476cb12d109161a9c0e6c9364d1d8aeca37e94045d166f88b5351d74b588ca998c9fd40b3744534fd75fc464ec868a4e171b0d32a2371c457b4898dfb613d68e44a02d0d12813ed65f8a3cb3682d4326889af1921f40d29049e272b582ae63326427f3726bef6e446e009709e07b391ba9ee5f96f9130f22c979991ff13c0fffee1375d5daac631ae429f660d3d98f0491a822a00c661327fde4fdfa743d05726c0ae2de1add48ca8d1daba4cff4cdd363402155ce97dfce6ed439c057886594cbdbf6e8213a56ca7ef95ed13b38103f3eda0e319d039e403375f6b9da0d17f572babd1926d3d7ad0b6cb937e0242a0e0701841e0b3433a450eee24fd46f69995ba0238bba26b27ce00012294c9d9d24c7ef115523417ea32360c1e344d8753c8efca58e2b314aed619b408839df1f4688dd08a2afa93d403707e3c3a2f09da2297b022e1c85fde777b8b6e8899f2461d1c82cc8463480513c779dc06ee5a676310cf38fac2e6a71ad467f2007d2ef68800391621d2a9ecbcc4798518a6311423afaf06e0d50a2c113106c19d2b50ccf52afb7b0834f4a407f5627543a5c8e93a72db019a3a7752d39997ed6648b6efc3cefb2db4860593415b3c99fbbd80d07ad936a6857d0aeffd3bbad17e99979e611843305efa517462a940312641c67b813da6a4f0734319c89e6928184988fa065cdff3b5f0bff8efecaeead513f765c75bca7d221181cd7889267d2e28a668e9b5e1c3382d7c5fcf42cb3acef5262db88b9760cab533e885ee2499463c3976b03dbe589bb523dd724f7e4fd30bedb56054ebe2c6c5e8dda768de47319c22782a44d663cc93a19b3c67e6e961ddabd42b6892de813222bf242fdf944f49a922c5cc66d4070b14715ef42646cad88bbbf5138fb4cfc93341e178588cfb2d297892a8af0d8dddb003f2350fcd9e8d45b6d5bd171a65da8f8535bb12b8f03a665584bc16dff9b754db1ba77def73e17827ffc236a91f1dd3740c58e064bbf4d070d3bd1662af122a36bd31b662bc41f88c79fe352cf9790d97d06ffd558ca08e43124131e9088a4957292c9a924cc40297a2c990559251087229f6809472ca75b7d6142aaacb94472d600fb3bf686ea2dc8ec34cad065b5108fa0d419b54fdbfa90083ce329033d56e4599ae6449d52571e8418c6bd825d9d3a3cb2f15ffb7609edb7bee790594cb0ac2f61c1b7062a22eed1bf8210b0820cd08f2b4ccd1731e521f06f29326e546c7ecb50d649dde92e6b85932316166ec256bf5bf0b86cd6f323c3db955fe2ca4ff91db618160a59a74c9c023131d04b1ae91628b0cf0581534046115ce9881392c24ff086a786f454dfa8b847a50826a923ba6ffcaf052deb654ef0029be4f56c23c836ef3223e11a1c9c183f72dbbe87cbeddae9d22be2b6eba17e3b5f0db41c8d1a6d9664b9b16e58f419ebdc67f6e8a129252b76c3f0d94db778cad43a7d7c8e46f4b12d6c4c3b4ba804ad24c961ecb2d3e8e44c487281c6827170263fefbb2404bcb7a98addc9eae24ea482123adecc358baeef9bebbb8bbe27032678ab0ef59765599b56928a2586a3c664bba64b87d73487df031dc2bd8b06a947da987706eb10b546af4a953be70debe8ad468f4af9d2639d3cca96ecaed4acde5deb3107e28f2684239e071c63b299a6ec9d2861184dccd6e09dec5082748b2f3df73a12a45a2caf05d9639ba9d4643e2f8d5d0335693e4be7bacf06c52231c9fb824a171070020020da72369cf3c6d38c84a9bca1dffa2ac2845b6f9ba00ed406272281ebae07700506c78581849ee86b4141f6f156eb3becfbc1e33566d4dc76e76f083be7764147d5a9451a3882983faead7eea5135654482bc6bd83e651a63e197d4ddee9f0372c355aae6cf71f39c828afb21050910d68"; // Prio3Aes128Sum, bits = 16
    const ENCODED_REPORT: &str = "a8a8e4ae7bcb879cf63b10538cc30c4a4b9d569257fc44a96ec2b46ba208a8aa00000000629006599e6273ab1f3c59040000021acb0020a1e9dd28d3e347aac558784f2b946f2488a664c1f7f7ca963df2d5b1929ee91e0180bcf16ade48f5effd2dac16d0fe0f1ae6b75b4bf8d8dd89d2cd431059b19f9747c137440aef19755733e7c3d45c0c85160dd496f660ba6e6d74e222780db94f976e1dbf9fed1a2c2679e2051424c415ee819901e05503b0299d960aa956d64bc37cdcf9df753491abdff99e4fb043817fb9e69776d9afa4d7dbfbeac0610f089301b8258dd0c6b618fdd9ba1d350c746a84f22291ef2ff6cc3a5773069cb5f243fd2e05214b09e946ddf6ecd7050dd5a742a9a23900a4f079afbfa03fb5ac5e4fdd8afe4fe98dd320538f6dcb7d614069715475531dc8d549dab3b167461b11425506a74644fa0c0617c1aa4e5eb8d385d31e31d113b26738898805975752a00bf3dc2be7c0fb1cf0a99354eaa3df4efd7c18ae6bf781875fd9cf3a88af27e8a235a9deda840bd4a1323052ebaec5dce45bde17f9c98371ae70437298ca35d6c2945b4d253bb1fdea2f47cba38636de2ff60161768568412f8af6885ecda986293a1e9f6a5cb4528d41becab7510d34f8e5cd536b2ab0a2cdc9314225835336b9070020ef53cdec6412253573b8efee347cdeb55aca7ed6643d028811fe68bd715b54640050d019d32b41dcbf68170186a8cf2ef8ec96f272e0b3fd06e65997103d17408fc1adeb9c38390098cd6db12f86b7747361538fcb5d57606af1cd66908500b10638e01276e917653c1a94b0c12bb81e65c0"; // Prio3Aes128Histogram, buckets = [1, 10, 100, 1000]
    let report = Report::get_decoded(&hex::decode(ENCODED_REPORT).unwrap()).unwrap();
    println!("Decoded report: {:?}", report);

    // Decrypt/decode input shares from report.
    type Vdaf = Prio3Aes128Histogram;
    // let vdaf = Vdaf::new(2).unwrap(); // Prio3Aes128Count
    // let vdaf = Prio3Aes128Sum::new(2, 16).unwrap(); // Prio3Aes128Sum
    let vdaf = Prio3Aes128Histogram::new(2, &[1, 10, 100, 1000]).unwrap(); //Prio3Aes128Histogram
    let (_, verify_params) = vdaf.setup().unwrap();
    let encoded_leader_input_share = hpke::open(
        &leader_hpke_config,
        &leader_hpke_private_key,
        &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader),
        report.encrypted_input_shares().get(0).unwrap(),
        &associated_data_for_report_share(task_id, report.nonce(), report.extensions()),
    )
    .unwrap();
    let leader_input_share = <Vdaf as vdaf::Vdaf>::InputShare::get_decoded_with_param(
        verify_params.get(0).unwrap(),
        &encoded_leader_input_share,
    )
    .unwrap();
    println!(
        "Decrypted/decoded leader input share: {:?}",
        leader_input_share
    );

    let encoded_helper_input_share = hpke::open(
        &helper_hpke_config,
        &helper_hpke_private_key,
        &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Helper),
        report.encrypted_input_shares().get(1).unwrap(),
        &associated_data_for_report_share(task_id, report.nonce(), report.extensions()),
    )
    .unwrap();
    let helper_input_share = <Vdaf as vdaf::Vdaf>::InputShare::get_decoded_with_param(
        verify_params.get(1).unwrap(),
        &encoded_helper_input_share,
    )
    .unwrap();
    println!(
        "Decrypted/decoded helper input share: {:?}",
        helper_input_share
    );

    // Run VDAF to recover output shares.
    let vdaf_transcript = run_vdaf(
        &vdaf,
        &verify_params,
        &(),
        report.nonce(),
        &[leader_input_share, helper_input_share],
    );
    let leader_output_share = assert_matches!(vdaf_transcript.transitions.get(0).unwrap().last().unwrap(), PrepareTransition::<Vdaf>::Finish(output_share) => output_share.clone());
    println!("Recovered leader output share: {:?}", leader_output_share);
    let helper_output_share = assert_matches!(vdaf_transcript.transitions.get(1).unwrap().last().unwrap(), PrepareTransition::<Vdaf>::Finish(output_share) => output_share.clone());
    println!("Recovered helper output share: {:?}", helper_output_share);

    // Convert output shares into aggregate shares (comprised of a single output share).
    let leader_aggregate_share = vdaf.aggregate(&(), [leader_output_share]).unwrap();
    println!("Leader aggregate share: {:?}", leader_aggregate_share);
    let helper_aggregate_share = vdaf.aggregate(&(), [helper_output_share]).unwrap();
    println!("Helper aggregate share: {:?}", helper_aggregate_share);

    // Unshard aggregate shares into a final result.
    let aggregate_result = vdaf
        .unshard(&(), [leader_aggregate_share, helper_aggregate_share])
        .unwrap();
    println!("Aggregate result: {:?}", aggregate_result);
}

fn print_hpke_config_and_private_key(hpke_config: &HpkeConfig, hpke_private_key: &HpkePrivateKey) {
    println!("HpkeConfig = {:?}", hpke_config);
    println!(
        "HpkePrivateKey = {}",
        hex::encode(hpke_private_key.as_ref())
    );
}

/// run_vdaf runs a VDAF state machine from sharding through to generating an output share,
/// returning a "transcript" of all states & messages.
// XXX: if this somehow ends up being merged to main, adapt janus_test_util::run_vdaf instead of copying
pub fn run_vdaf<V: vdaf::Aggregator + vdaf::Client>(
    vdaf: &V,
    verify_params: &[V::VerifyParam],
    aggregation_param: &V::AggregationParam,
    nonce: Nonce,
    input_shares: &[V::InputShare],
) -> VdafTranscript<V>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    assert_eq!(vdaf.num_aggregators(), verify_params.len());
    assert_eq!(vdaf.num_aggregators(), input_shares.len());

    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let mut prep_trans: Vec<Vec<PrepareTransition<V>>> = input_shares
        .iter()
        .zip(verify_params)
        .map(|(input_share, verify_param)| {
            let prep_step = vdaf.prepare_init(
                verify_param,
                aggregation_param,
                &nonce.get_encoded(),
                input_share,
            )?;
            let prep_trans = vdaf.prepare_step(prep_step, None);
            Ok(vec![prep_trans])
        })
        .collect::<Result<Vec<Vec<PrepareTransition<V>>>, VdafError>>()
        .unwrap();
    let mut combined_prep_msgs = Vec::new();

    // Repeatedly step the VDAF until we reach a terminal state.
    loop {
        // Gather messages from last round & combine them into next round's message; if any
        // participants have reached a terminal state (Finish or Fail), we are done.
        let mut prep_msgs = Vec::new();
        for pts in &prep_trans {
            match pts.last().unwrap() {
                PrepareTransition::<V>::Continue(_, prep_msg) => prep_msgs.push(prep_msg.clone()),
                _ => {
                    return VdafTranscript {
                        input_shares: input_shares.to_vec(),
                        transitions: prep_trans,
                        combined_messages: combined_prep_msgs,
                    }
                }
            }
        }
        let combined_prep_msg = vdaf.prepare_preprocess(prep_msgs).unwrap();
        combined_prep_msgs.push(combined_prep_msg.clone());

        // Compute each participant's next transition.
        for pts in &mut prep_trans {
            let prep_step = assert_matches!(pts.last().unwrap(), PrepareTransition::<V>::Continue(prep_step, _) => prep_step).clone();
            pts.push(vdaf.prepare_step(prep_step, Some(combined_prep_msg.clone())));
        }
    }
}
