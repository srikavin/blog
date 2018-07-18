import React from 'react'
import './Resume.css'

class Resume extends React.Component {
    render() {
        return (
            <div className={'landingResumeButton'}
                 onClick={() => {
                     window.open(process.env.PUBLIC_URL + '/resume.pdf', '_blank')
                 }}> Resume</div>
        );
    }
}

export default Resume;