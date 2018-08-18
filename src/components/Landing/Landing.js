import React from 'react'
import './Landing.css'
import About from './About/About';
import Portfolio from './Portolio/Portfolio';
import Resume from './Resume/Resume'
import DocumentTitle from 'react-document-title'

class Landing extends React.Component {
    render() {
        return (
            <div className={'landingContainer'}>
                <DocumentTitle title='About'/>
                <About/>
                <Portfolio/>
                <Resume/>
            </div>
        );
    }
}

export default Landing;