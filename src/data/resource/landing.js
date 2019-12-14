//@flow
import axios from './_common';


interface LandingResource {
    getLanding(): Promise<string>;
}

let LandingFetcher: LandingResource = {
    getLanding() {
        return axios.get('/landing')
            .then(e => e.data);
    },
};

export const LandingStore: LandingResource = LandingFetcher;