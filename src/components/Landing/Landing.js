import React from 'react'
import styles from './Landing.module.css'
import About from './About/About';
import Portfolio from './Portolio/Portfolio';
import Resume from './Resume/Resume'
import {Helmet} from "react-helmet";

class Landing extends React.Component {
    render() {
        return (
            <div className={styles.landingContainer}>
                <Helmet>
                    <title>About</title>
                </Helmet>
                <About/>
                <Portfolio/>
                <br/>
                <Resume/>
            </div>
        );
    }
}

export default Landing;