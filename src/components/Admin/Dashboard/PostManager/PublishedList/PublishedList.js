import React, {Component} from 'react';
import {PostStore} from '../../../../../data/resource/post';
import PostCrudList from '../../PostManager/PostCrudList/PostCrudList';

class PublishedList extends Component {
    constructor(props) {
        super(props);
        this.state = {
            posts: []
        };
    }


    componentDidMount() {
        PostStore.getAll(true).then(e => {
            this.setState({
                posts: e
            });
        })
    }

    render() {
        return (
            <PostCrudList updateItems={(posts) => this.setState({posts})} items={this.state.posts}/>
        );
    }
}

PublishedList.propTypes = {};

export default PublishedList;