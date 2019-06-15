import React from 'react'
import styles from './Resume.module.css'

class Resume extends React.Component {
    render() {
        return (
            <a href={process.env.PUBLIC_URL + '/resume.pdf'}>
                <div className={styles.landingResumeButton}>Resume</div>
            </a>
        );
    }
}

export default Resume;