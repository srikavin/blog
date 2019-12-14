import React from 'react'
import styles from './Landing.module.css'
import Portfolio from './Portolio/Portfolio';
import Resume from './Resume/Resume'
import {Helmet} from "react-helmet";
import MathRenderer from "../Post/PostContent/MathRenderer/MathRenderer";
import config from '../../config'
import {LandingStore} from "../../data/resource/landing";


class Landing extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            md: undefined
        }
    }


    componentDidMount() {
        if (config.homepage.useLandingPage) {
            LandingStore.getLanding().then(md => {
                this.setState({
                    md
                });
            });
        }
    }

    render() {
        return (
            <div className={styles.landingContainer}>
                <Helmet>
                    <title>About</title>
                </Helmet>

                {config.homepage.useLandingPage ? (
                    <div style={{fontSize: 18}}>
                        {this.state.md ? (
                            <MathRenderer source={this.state.md} trusted={true}/>
                        ) : null}
                    </div>
                ) : null}

                {config.homepage.usePortfolio ? <Portfolio items={config.homepage.portfolio}/> : null}

                <br/>
                {config.homepage.useResume ? <Resume/> : null}
            </div>
        );
    }
}

export default Landing;